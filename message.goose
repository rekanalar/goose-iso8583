namespace iso8583;

import std;

// True when id names a field that a caller may set: 2 to the top field,
// without the field that holds the secondary bitmap indicator.
fn valid_id(id: i64) -> bool {
    return id >= 2 && id <= MAX_FIELD_ID && id != 65;
}

// OK when v is a legal MTI: four ASCII digits.
fn mti_ok(v: const u8[:]) -> bool {
    if v.len != 4 { return false; }
    for i in 0..4 { if !is_digit(v[i]) { return false; } }
    return true;
}

// Empties a message and zeroes the old bytes. Only the buffer of this
// value is cleared. Copies that the caller made stay as they are.
fn message_clear(msg: Message&) {
    fill(msg.data, 0);
    msg.data.clear();
    msg.mti.clear();
    msg.fault_field = 0;
    msg.live = 0;
    msg.holes = 0;
    for i in 0..193 { msg.slots[i] = Slot { .. }; }
}

// Sets the MTI: four ASCII digits in the logical form.
fn message_set_mti(msg: Message&, mti: const u8[:]) -> i64 {
    if !mti_ok(mti) { return ERR_BAD_MTI; }
    msg.mti.clear();
    msg.mti.append(mti);
    return OK;
}

// OK when v is a legal value of the field under the dialect. Set and pack
// both use it, so a value set under one dialect cannot slip into another.
fn check_value(d: Dialect&, id: i64, v: const u8[:]) -> i64 {
    if !valid_id(id) { return ERR_BAD_FIELD_ID; }
    if !d.fields[id].defined { return ERR_UNKNOWN_FIELD; }
    let spec = d.fields[id];
    let maxv = value_len(spec.enc, spec.unit, spec.max_len);
    if v.len > maxv { return ERR_VALUE_LENGTH; }
    if spec.kind == KIND_FIXED && spec.pad_char < 0 && v.len != maxv { return ERR_VALUE_LENGTH; }
    if units_of(spec.enc, spec.unit, v.len) < 0 { return ERR_VALUE_LENGTH; }
    if spec.pad_char >= 0 && pad_unsafe(v, spec.padding, spec.pad_char as u8) { return ERR_VALUE_LENGTH; }
    if spec.composite != COMPOSITE_NONE {
        let r = container_check(d, id, spec.composite, v, 0, v.len, 1);
        if r != OK { return r; }
    }
    return check_alphabet(spec.enc, v);
}

// Zeroes a run of the data buffer.
fn zero_range(v: u8[>..]&, start: i64, len: i64) {
    for i in 0..len { v[start + i] = 0; }
}

// Moves the bytes of every present slot to the front and cuts the
// tail. The slots move in the order of their offsets, because the
// buffer holds the fields in the order they were set. The offsets
// change; the caller checks the limit first.
fn compact(msg: Message&) {
    // The present slots, sorted by their offsets.
    var ids: i64[193] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    var n = 0;
    for k in 2..193 {
        if !msg.slots[k].present { continue; }
        ids[n] = k;
        n += 1;
    }
    for i in 1..n {
        let v = ids[i];
        var j = i - 1;
        while j >= 0 && msg.slots[ids[j]].off > msg.slots[v].off {
            ids[j + 1] = ids[j];
            j -= 1;
        }
        ids[j + 1] = v;
    }
    var at: i64 = 0;
    for i in 0..n {
        let k = ids[i];
        let s = msg.slots[k];
        if s.off != at {
            // The copy runs from the low index to the high one, so the
            // source and the target may overlap.
            for j in 0..s.len { msg.data[at + j] = msg.data[s.off + j]; }
            msg.slots[k].off = at;
        }
        at += s.len;
    }
    // The live fields cover the front of the buffer. The rest holds
    // stale bytes, and the copy above erased them.
    zero_range(msg.data, at, msg.data.len - at);
    msg.data.resize(at);
    msg.holes = 0;
}

// Removes the bytes of one field in place: the old bytes become a hole
// of zeros. A hole at the end is cut at once. Only a full buffer
// triggers a compaction, so one set never touches other fields.
fn slot_drop(msg: Message&, id: i64) {
    if !msg.slots[id].present { return; }
    let s = msg.slots[id];
    msg.live -= s.len;
    msg.holes += 1;
    zero_range(msg.data, s.off, s.len);
    if s.off + s.len == msg.data.len {
        msg.data.resize(s.off);
        msg.holes -= 1;
    }
    msg.slots[id] = Slot { .. };
}

// Sets a field. The value must fit the dialect. A second set replaces the
// first. The message data stays within MAX_INPUT bytes.
fn message_set(msg: Message&, d: Dialect&, id: i64, v: const u8[:]) -> i64 {
    let f = check_value(d, id, v);
    if f != OK { return f; }
    // A replacement of a present field reuses its bytes when the new
    // value is not longer.
    let s = msg.slots[id];
    if s.present && v.len <= s.len {
        for i in 0..v.len { msg.data[s.off + i] = v[i]; }
        zero_range(msg.data, s.off + v.len, s.len - v.len);
        msg.live -= s.len - v.len;
        if s.off + s.len == msg.data.len {
            msg.data.resize(s.off + v.len);
        } else {
            // The freed bytes stay in the buffer. The gap lets a
            // compaction give the room back.
            msg.holes += 1;
        }
        msg.slots[id].len = v.len;
        return OK;
    }
    // Compact once when the append would push the buffer over its
    // limit and holes leave room. The live count is the real limit.
    if msg.data.len + v.len > MAX_INPUT && msg.holes > 0 { compact(msg); }
    var live_after = msg.live + v.len;
    if s.present { live_after -= s.len; }
    if live_after > MAX_INPUT { return ERR_FULL; }
    slot_drop(msg, id);
    msg.slots[id] = Slot { present: true, off: msg.data.len, len: v.len };
    msg.live += v.len;
    msg.data.append(v);
    return OK;
}

// Copies the value of a field into out.
fn message_get(msg: Message&, id: i64, out: u8[>..]&) -> i64 {
    out.clear();
    if id < 2 || id > MAX_FIELD_ID { return ERR_BAD_FIELD_ID; }
    let s = msg.slots[id];
    if !s.present { return ERR_NOT_SET; }
    if s.off < 0 || s.len < 0 || s.off + s.len > msg.data.len { return ERR_BAD_ARG; }
    out.append(msg.data[s.off..s.off + s.len]);
    return OK;
}

fn message_has(msg: Message&, id: i64) -> bool {
    if !valid_id(id) { return false; }
    return msg.slots[id].present;
}

// Removes a field.
fn message_unset(msg: Message&, id: i64) -> i64 {
    if !valid_id(id) { return ERR_BAD_FIELD_ID; }
    if !msg.slots[id].present { return ERR_NOT_SET; }
    slot_drop(msg, id);
    return OK;
}

// ---- subfields -------------------------------------------------------

// The result of a walk down to a subfield. depth is the level that
// holds the target, counted from 0. index is the index of the target
// entry in that level, or -1 when the target is not there. mode0 to
// mode2 are the container modes of the levels, p0 and p1 the entries of
// the levels above the target, and base1 and base2 the offsets of the
// payloads of level 1 and 2 in the buffer of the field. The offsets of
// the entries of a level count from the start of its payload.
struct Found {
    depth: i64,
    index: i64,
    cont: i64,
    mode0: i64,
    mode1: i64,
    mode2: i64,
    p0: i64,
    p1: i64,
    base1: i64,
    base2: i64,
    lv0: Level,
    lv1: Level,
    lv2: Level,
}

// The index of the entry of the level that has the tag. -1 when there is
// none.
fn find_entry(lvl: Level&, tag: i64) -> i64 {
    for k in 0..lvl.count {
        if lvl.ents[k].tag == tag { return k; }
    }
    return -1;
}

// The mode of the level the target sits in.
fn found_mode(f: Found&) -> i64 {
    if f.depth == 0 { return f.mode0; }
    if f.depth == 1 { return f.mode1; }
    return f.mode2;
}

// The base offset of the payload of the level the target sits in.
fn found_base(f: Found&) -> i64 {
    if f.depth == 0 { return 0; }
    if f.depth == 1 { return f.base1; }
    return f.base2;
}

// The entry of the target.
fn found_entry(f: Found&) -> Entry {
    if f.depth == 0 { return f.lv0.ents[f.index]; }
    if f.depth == 1 { return f.lv1.ents[f.index]; }
    return f.lv2.ents[f.index];
}

// Walks down to the subfield that the path names. buf holds the payload
// of the field. A fault code means that the payload does not hold the
// path. A container above the target must exist (ERR_NOT_SET).
fn walk_sub(d: Dialect&, path: Path, buf: const u8[:], f: Found&) -> i64 {
    if path.n < 2 || path.n > MAX_PATH { return ERR_BAD_ARG; }
    let fid = path.ids[0];
    if !valid_id(fid) { return ERR_BAD_FIELD_ID; }
    if !d.fields[fid].defined { return ERR_UNKNOWN_FIELD; }
    if d.fields[fid].composite == COMPOSITE_NONE { return ERR_BAD_ARG; }
    var cont = fid;
    var mode = d.fields[fid].composite;
    var base = 0;
    f.depth = 0;
    f.index = -1;
    f.p0 = -1;
    f.p1 = -1;
    f.base1 = 0;
    f.base2 = 0;
    f.mode0 = mode;
    for i in 1..path.n {
        let view = buf[base..buf.len];
        var k = -1;
        var e = Entry { .. };
        if f.depth == 0 {
            let n, ff = parse_level(d, cont, mode, view, 0, view.len, f.lv0);
            if ff != OK { return ff; }
            k = find_entry(f.lv0, path.ids[i]);
            if k >= 0 { e = f.lv0.ents[k]; }
        } else if f.depth == 1 {
            let n, ff = parse_level(d, cont, mode, view, 0, view.len, f.lv1);
            if ff != OK { return ff; }
            k = find_entry(f.lv1, path.ids[i]);
            if k >= 0 { e = f.lv1.ents[k]; }
        } else {
            let n, ff = parse_level(d, cont, mode, view, 0, view.len, f.lv2);
            if ff != OK { return ff; }
            k = find_entry(f.lv2, path.ids[i]);
            if k >= 0 { e = f.lv2.ents[k]; }
        }
        f.cont = cont;
        if k < 0 {
            if i < path.n - 1 { return ERR_NOT_SET; }
            f.index = -1;
            return OK;
        }
        if i == path.n - 1 {
            f.index = k;
            return OK;
        }
        if d.subs[e.sub].composite == COMPOSITE_NONE { return ERR_BAD_ARG; }
        if f.depth == 0 { f.p0 = k; } else if f.depth == 1 { f.p1 = k; }
        base = base + e.off;
        cont = 1000 + e.sub;
        mode = d.subs[e.sub].composite;
        if f.depth == 0 {
            f.mode1 = mode;
            f.base1 = base;
        } else {
            f.mode2 = mode;
            f.base2 = base;
        }
        f.depth += 1;
    }
    return ERR_BAD_ARG;
}

// Checks the logical value of a subfield against its spec. A subfield
// that is a container holds a payload of its own.
fn check_sub_value(d: Dialect&, si: i64, spec: FieldSpec, v: const u8[:]) -> i64 {
    let maxv = value_len(spec.enc, spec.unit, spec.max_len);
    if maxv < 0 { return ERR_BAD_ARG; }
    if v.len > maxv { return ERR_VALUE_LENGTH; }
    if spec.kind == KIND_FIXED && spec.pad_char < 0 && v.len != maxv { return ERR_VALUE_LENGTH; }
    if units_of(spec.enc, spec.unit, v.len) < 0 { return ERR_VALUE_LENGTH; }
    if spec.pad_char >= 0 && pad_unsafe(v, spec.padding, spec.pad_char as u8) { return ERR_VALUE_LENGTH; }
    let a = check_alphabet(spec.enc, v);
    if a != OK { return a; }
    if spec.composite != COMPOSITE_NONE {
        return container_check(d, 1000 + si, spec.composite, v, 0, v.len, 1);
    }
    return OK;
}

// Copies the payload of the field to buf. ERR_NOT_SET when it is absent.
fn field_payload(msg: Message&, fid: i64, buf: u8[>..]&) -> i64 {
    buf.clear();
    if !msg.slots[fid].present { return ERR_NOT_SET; }
    let s = msg.slots[fid];
    if s.off < 0 || s.len < 0 || s.off + s.len > msg.data.len { return ERR_BAD_ARG; }
    buf.append(msg.data[s.off..s.off + s.len]);
    return OK;
}

// Copies the value of a subfield into out, in its logical form.
fn message_get_sub(msg: Message&, d: Dialect&, path: Path, out: u8[>..]&) -> i64 {
    out.clear();
    if path.n < 2 || path.n > MAX_PATH { return ERR_BAD_ARG; }
    let fid = path.ids[0];
    if !valid_id(fid) { return ERR_BAD_FIELD_ID; }
    var buf: u8[>..] = [];
    let r = field_payload(msg, fid, buf);
    if r != OK { return r; }
    var f = Found { .. };
    let code = walk_sub(d, path, buf, f);
    if code != OK { return code; }
    if f.index < 0 { return ERR_NOT_SET; }
    let e = found_entry(f);
    let at = found_base(f) + e.off;
    if at < 0 || e.len < 0 || at + e.len > buf.len { return ERR_BAD_ARG; }
    let spec = d.subs[e.sub];
    return decode_field_value(out, spec, buf[at..at + e.len], e.vlen, d.page);
}

// True when the subfield is there.
fn message_has_sub(msg: Message&, d: Dialect&, path: Path) -> bool {
    if path.n < 2 || path.n > MAX_PATH { return false; }
    let fid = path.ids[0];
    if !valid_id(fid) { return false; }
    var buf: u8[>..] = [];
    if field_payload(msg, fid, buf) != OK { return false; }
    var f = Found { .. };
    if walk_sub(d, path, buf, f) != OK { return false; }
    return f.index >= 0;
}

// Rebuilds the levels from the one that holds the target up to the field
// and returns the new payload of the field in out. wire holds the new
// wire bytes of the target and vlen their logical length. drop removes
// the target and add appends it as a new entry.
fn rebuild_up(d: Dialect&, f: Found&, buf: const u8[:], wire: const u8[:], vlen: i64, drop: bool, add: bool, tag: i64, si: i64, out: u8[>..]&) -> i64 {
    var a: u8[>..] = [];
    var b: u8[>..] = [];
    let extra = Entry { tag: tag, sub: si, off: 0, len: 0, vlen: vlen };
    var drop_at = -1;
    var change_at = -1;
    if drop { drop_at = f.index; } else if !add { change_at = f.index; }
    // The level of the target.
    var r = OK;
    if f.depth == 0 {
        r = rebuild(d, f.mode0, f.lv0, buf, change_at, drop_at, extra, add, wire, vlen, out);
        return r;
    }
    if f.depth == 1 {
        r = rebuild(d, f.mode1, f.lv1, buf[f.base1..buf.len], change_at, drop_at, extra, add, wire, vlen, a);
        if r != OK { return r; }
        return rebuild(d, f.mode0, f.lv0, buf, f.p0, -1, extra, false, a, a.len, out);
    }
    r = rebuild(d, f.mode2, f.lv2, buf[f.base2..buf.len], change_at, drop_at, extra, add, wire, vlen, a);
    if r != OK { return r; }
    r = rebuild(d, f.mode1, f.lv1, buf[f.base1..buf.len], f.p1, -1, extra, false, a, a.len, b);
    if r != OK { return r; }
    return rebuild(d, f.mode0, f.lv0, buf, f.p0, -1, extra, false, b, b.len, out);
}

// Sets a subfield. The container is made when it is not there, unless it
// is a list. A new tag goes last, so the wire order of the other entries
// holds. A container above the target must exist.
fn message_set_sub(msg: Message&, d: Dialect&, path: Path, v: const u8[:]) -> i64 {
    if path.n < 2 || path.n > MAX_PATH { return ERR_BAD_ARG; }
    let fid = path.ids[0];
    if !valid_id(fid) { return ERR_BAD_FIELD_ID; }
    if !d.fields[fid].defined { return ERR_UNKNOWN_FIELD; }
    var buf: u8[>..] = [];
    if msg.slots[fid].present {
        let r = field_payload(msg, fid, buf);
        if r != OK { return r; }
    } else if d.fields[fid].composite == COMPOSITE_LIST {
        // A list holds all its subfields, so it cannot start empty.
        return ERR_NOT_SET;
    }
    var f = Found { .. };
    let code = walk_sub(d, path, buf, f);
    if code != OK { return code; }
    var si = -1;
    var add = false;
    if f.index >= 0 {
        si = found_entry(f).sub;
    } else {
        si = find_sub(d, f.cont, path.ids[path.n - 1]);
        if si < 0 { return ERR_BAD_TAG; }
        add = true;
    }
    let spec = d.subs[si];
    let cv = check_sub_value(d, si, spec, v);
    if cv != OK { return cv; }
    var wire: u8[>..] = [];
    encode_value(wire, spec.enc, spec.padding, spec.pad_digit, v, d.page);
    var out: u8[>..] = [];
    let r = rebuild_up(d, f, buf, wire, v.len, false, add, path.ids[path.n - 1], si, out);
    if r != OK { return r; }
    return message_set(msg, d, fid, out);
}

// Removes a subfield. The other entries keep their order. A list is
// positional, so a subfield cannot leave it.
fn message_unset_sub(msg: Message&, d: Dialect&, path: Path) -> i64 {
    if path.n < 2 || path.n > MAX_PATH { return ERR_BAD_ARG; }
    let fid = path.ids[0];
    if !valid_id(fid) { return ERR_BAD_FIELD_ID; }
    var buf: u8[>..] = [];
    let r0 = field_payload(msg, fid, buf);
    if r0 != OK { return r0; }
    var f = Found { .. };
    let code = walk_sub(d, path, buf, f);
    if code != OK { return code; }
    if f.index < 0 { return ERR_NOT_SET; }
    if found_mode(f) == COMPOSITE_LIST { return ERR_BAD_ARG; }
    var out: u8[>..] = [];
    let r = rebuild_up(d, f, buf, "", 0, true, false, 0, 0, out);
    if r != OK { return r; }
    return message_set(msg, d, fid, out);
}

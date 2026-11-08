// The composite fields of the package: a field that holds subfields, a
// list of subfields, a list of tagged subfields, or a BER-TLV container.
//
// The walk uses fixed arrays and no recursion over growable values. Every
// length, count and depth is checked before the work that uses it.
namespace iso8583;

import std;

// One entry of a container level. tag is the tag value, or the 1-based
// position in a list. sub is the index of the subfield spec. off and len
// give the value in the buffer of the container.
struct Entry {
    tag: i64,
    sub: i64,
    off: i64,
    len: i64,
    vlen: i64,
}

// One level of a container walk. The entries array is fixed, so a level
// never grows.
struct Level {
    cont: i64,
    mode: i64,
    count: i64,
    ents: Entry[64],
}

// A path to a top-level field.
fn path1(id: i64) -> Path {
    var p = Path { .. };
    p.ids[0] = id;
    p.n = 1;
    return p;
}

// A path to a subfield of a top-level field.
fn path2(id: i64, a: i64) -> Path {
    var p = path1(id);
    p.ids[1] = a;
    p.n = 2;
    return p;
}

// A path to a subfield of a subfield.
fn path3(id: i64, a: i64, b: i64) -> Path {
    var p = path2(id, a);
    p.ids[2] = b;
    p.n = 3;
    return p;
}

// The deepest path of the package.
fn path4(id: i64, a: i64, b: i64, c: i64) -> Path {
    var p = path3(id, a, b);
    p.ids[3] = c;
    p.n = 4;
    return p;
}

// True when the path names a field and at most MAX_PATH levels.
fn path_valid(p: Path) -> bool {
    if p.n < 1 || p.n > MAX_PATH { return false; }
    return true;
}

// ---- containers ------------------------------------------------------

// The spec of a container. A top-level field uses its field id. A
// subfield that is a container uses 1000 plus the index of the sub.
fn container_spec(d: Dialect&, cont: i64) -> FieldSpec {
    if cont <= MAX_FIELD_ID { return d.fields[cont]; }
    return d.subs[cont - 1000];
}

// The index of the subfield of cont that has the tag. -1 when there is
// none.
fn find_sub(d: Dialect&, cont: i64, tag: i64) -> i64 {
    for i in 0..192 {
        if !d.subs[i].defined { continue; }
        if d.subs[i].parent != cont { continue; }
        if d.subs[i].tag == tag { return i; }
    }
    return -1;
}

// The count of the subfields of cont.
fn sub_count(d: Dialect&, cont: i64) -> i64 {
    var n = 0;
    for i in 0..192 {
        if !d.subs[i].defined { continue; }
        if d.subs[i].parent == cont { n += 1; }
    }
    return n;
}

// ---- BER tags and lengths --------------------------------------------

// The number of bytes of the BER tag of the value v. -1 when the value
// has no tag form of at most three bytes. The shortest form wins, so
// one value has one form.
fn ber_tag_len(v: i64) -> i64 {
    if v < 0 || v > 16777215 { return -1; }
    var k = 1;
    while k <= 3 {
        // The value must need exactly k bytes.
        if (v >> (8 * k)) != 0 { k += 1; continue; }
        var b: i64[3] = [0, 0, 0];
        var ok = true;
        for i in 0..k {
            b[i] = (v >> (8 * (k - 1 - i))) & 255;
        }
        if (b[0] & 31) != 31 {
            ok = k == 1;
        } else {
            var last = 0;
            for i in 1..k {
                if (b[i] & 128) == 0 { last = i; break; }
            }
            if last == 0 { ok = false; } else { ok = last + 1 == k; }
        }
        if ok { return k; }
        k += 1;
    }
    return -1;
}

// Appends the BER tag of the value v.
fn ber_write_tag(out: u8[>..]&, v: i64) -> i64 {
    let k = ber_tag_len(v);
    if k < 0 { return ERR_BAD_TAG; }
    for i in 0..k {
        let shift = 8 * (k - 1 - i);
        out.push(((v >> shift) & 255) as u8);
    }
    return OK;
}

// Reads the BER tag at pos. Returns the value, the new position and a
// fault code. A tag of more than three bytes is ERR_BAD_TAG.
fn ber_read_tag(buf: const u8[:], pos: i64, end: i64) -> i64, i64, i64 {
    if pos >= end { return 0, pos, ERR_TRUNCATED; }
    var v = 0;
    var n = 1;
    let b0 = buf[pos] as i64;
    v = b0;
    if (b0 & 31) == 31 {
        n = 1;
        while true {
            if pos + n >= end { return 0, pos, ERR_TRUNCATED; }
            let b = buf[pos + n] as i64;
            v = (v << 8) | b;
            n += 1;
            if (b & 128) == 0 { break; }
            if n >= 3 { return 0, pos, ERR_BAD_TAG; }
        }
    }
    return v, pos + n, OK;
}

// Reads the BER length at pos. Returns the length, the new position and
// a fault code. A length that is not in its shortest form is
// ERR_BAD_LENGTH.
fn ber_read_len(buf: const u8[:], pos: i64, end: i64) -> i64, i64, i64 {
    if pos >= end { return 0, pos, ERR_TRUNCATED; }
    let b0 = buf[pos] as i64;
    if b0 < 128 { return b0, pos + 1, OK; }
    if b0 == 128 { return 0, pos, ERR_BAD_LENGTH; }
    if b0 == 129 {
        if pos + 2 > end { return 0, pos, ERR_TRUNCATED; }
        let l = buf[pos + 1] as i64;
        if l < 128 { return 0, pos, ERR_BAD_LENGTH; }
        return l, pos + 2, OK;
    }
    if b0 == 130 {
        if pos + 3 > end { return 0, pos, ERR_TRUNCATED; }
        let l = (buf[pos + 1] as i64) * 256 + buf[pos + 2];
        if l < 256 { return 0, pos, ERR_BAD_LENGTH; }
        if l > MAX_FIELD { return 0, pos, ERR_BAD_LENGTH; }
        return l, pos + 3, OK;
    }
    return 0, pos, ERR_BAD_LENGTH;
}

// Appends the BER length of a value of n bytes.
fn ber_write_len(out: u8[>..]&, n: i64) -> i64 {
    if n < 0 || n > MAX_FIELD { return ERR_BAD_LENGTH; }
    if n < 128 {
        out.push(n as u8);
        return OK;
    }
    if n < 256 {
        out.push(129);
        out.push(n as u8);
        return OK;
    }
    out.push(130);
    out.push((n / 256) as u8);
    out.push((n % 256) as u8);
    return OK;
}

// ---- the walk --------------------------------------------------------

// Reads the value of one subfield at pos. Returns the offset of the
// value, its wire length, its logical length, the new position and a
// fault code.
fn read_sub_value(d: Dialect&, spec: FieldSpec, buf: const u8[:], pos: i64, end: i64) -> i64, i64, i64, i64, i64 {
    if pos > end { return 0, 0, 0, pos, ERR_TRUNCATED; }
    if spec.kind == KIND_FIXED {
        let vlen = value_len(spec.enc, spec.unit, spec.max_len);
        if vlen < 0 { return 0, 0, 0, pos, ERR_BAD_ARG; }
        let wlen = wire_size(spec.enc, vlen);
        if pos + wlen > end { return 0, 0, 0, pos, ERR_TRUNCATED; }
        return pos, wlen, vlen, pos + wlen, OK;
    }
    let view = buf[pos..end];
    let n, f = get_prefix(view, 0, spec.prefix_enc, spec.kind, d.page);
    if f != OK { return 0, 0, 0, pos, f; }
    if n > spec.max_len { return 0, 0, 0, pos, ERR_BAD_LENGTH; }
    let vlen = value_len(spec.enc, spec.unit, n);
    let wlen = wire_size(spec.enc, vlen);
    let pw = prefix_width(spec.prefix_enc, spec.kind);
    if pos + pw + wlen > end { return 0, 0, 0, pos, ERR_TRUNCATED; }
    return pos + pw, wlen, vlen, pos + pw + wlen, OK;
}

// The value of a BER subfield of a length of n bytes must fit the spec.
fn ber_value_ok(spec: FieldSpec, n: i64) -> bool {
    let maxv = value_len(spec.enc, spec.unit, spec.max_len);
    if spec.kind == KIND_FIXED { return n == maxv; }
    return n <= maxv;
}

// Checks that the wire bytes of a leaf entry decode under its spec: the
// alphabet, a BCD nibble and the pad nibble. A nested container is
// checked by its own walk.
fn leaf_ok(d: Dialect&, spec: FieldSpec, buf: const u8[:], e: Entry) -> i64 {
    if spec.composite != COMPOSITE_NONE { return OK; }
    if e.off < 0 || e.len < 0 || e.off + e.len > buf.len { return ERR_BAD_ARG; }
    var tmp: u8[>..] = [];
    return decode_field_value(tmp, spec, buf[e.off..e.off + e.len], e.vlen, d.page);
}

// Parses one level of a container. The buffer holds the payload of the
// level; the level runs from start to end. Returns the count of entries
// and a fault code.
fn parse_level(d: Dialect&, cont: i64, mode: i64, buf: const u8[:], start: i64, end: i64, lvl: Level&) -> i64, i64 {
    lvl.cont = cont;
    lvl.mode = mode;
    lvl.count = 0;
    if start > end || end > buf.len { return 0, ERR_BAD_ARG; }
    if mode == COMPOSITE_LIST {
        // The subfields come in the order of their declaration. All of
        // them must be there.
        var pos = start;
        var k = 0;
        for i in 0..192 {
            if !d.subs[i].defined { continue; }
            if d.subs[i].parent != cont { continue; }
            if k >= 64 { return 0, ERR_BAD_ARG; }
            let off, wlen, vlen, np, f = read_sub_value(d, d.subs[i], buf, pos, end);
            if f != OK { return 0, f; }
            let e = Entry { tag: k + 1, sub: i, off: off, len: wlen, vlen: vlen };
            let g = leaf_ok(d, d.subs[i], buf, e);
            if g != OK { return 0, g; }
            lvl.ents[k] = e;
            k += 1;
            pos = np;
        }
        if pos != end { return 0, ERR_TRAILING; }
        lvl.count = k;
        return k, OK;
    }
    if mode == COMPOSITE_TAGGED {
        let cs = container_spec(d, cont);
        var pos = start;
        var k = 0;
        while pos < end {
            if k >= 64 { return 0, ERR_BAD_ARG; }
            if pos + cs.tag_width > end { return 0, ERR_TRUNCATED; }
            var tag = 0;
            for i in 0..cs.tag_width {
                let c = buf[pos + i];
                if !is_digit(c) { return 0, ERR_BAD_TAG; }
                tag = tag * 10 + (c - '0');
            }
            let si = find_sub(d, cont, tag);
            if si < 0 { return 0, ERR_BAD_TAG; }
            for j in 0..k {
                if lvl.ents[j].tag == tag { return 0, ERR_DUPLICATE; }
            }
            let off, wlen, vlen, np, f = read_sub_value(d, d.subs[si], buf, pos + cs.tag_width, end);
            if f != OK { return 0, f; }
            let e = Entry { tag: tag, sub: si, off: off, len: wlen, vlen: vlen };
            let g = leaf_ok(d, d.subs[si], buf, e);
            if g != OK { return 0, g; }
            lvl.ents[k] = e;
            k += 1;
            pos = np;
        }
        lvl.count = k;
        return k, OK;
    }
    if mode == COMPOSITE_BER {
        var pos = start;
        var k = 0;
        while pos < end {
            if k >= 64 { return 0, ERR_BAD_ARG; }
            let tag, np, f = ber_read_tag(buf, pos, end);
            if f != OK { return 0, f; }
            let si = find_sub(d, cont, tag);
            if si < 0 { return 0, ERR_BAD_TAG; }
            for j in 0..k {
                if lvl.ents[j].tag == tag { return 0, ERR_DUPLICATE; }
            }
            let len, np2, f2 = ber_read_len(buf, np, end);
            if f2 != OK { return 0, f2; }
            if !ber_value_ok(d.subs[si], len) { return 0, ERR_BAD_LENGTH; }
            if np2 + len > end { return 0, ERR_TRUNCATED; }
            let e = Entry { tag: tag, sub: si, off: np2, len: len, vlen: len };
            let g = leaf_ok(d, d.subs[si], buf, e);
            if g != OK { return 0, g; }
            lvl.ents[k] = e;
            k += 1;
            pos = np2 + len;
        }
        lvl.count = k;
        return k, OK;
    }
    return 0, ERR_BAD_ARG;
}

// Checks the payload of a composite field. Every nested container is
// checked too. The depth never passes MAX_DEPTH.
recursive fn container_check(d: Dialect&, cont: i64, mode: i64, buf: const u8[:], start: i64, end: i64, depth: i64) -> i64 {
    if depth > MAX_DEPTH { return ERR_DEPTH; }
    var lvl = Level { .. };
    let n, f = parse_level(d, cont, mode, buf, start, end, lvl);
    if f != OK { return f; }
    for k in 0..n {
        let si = lvl.ents[k].sub;
        if d.subs[si].composite == COMPOSITE_NONE { continue; }
        let r = container_check(d, 1000 + si, d.subs[si].composite, buf,
                                lvl.ents[k].off, lvl.ents[k].off + lvl.ents[k].len, depth + 1);
        if r != OK { return r; }
    }
    return OK;
}

// ---- rebuild ---------------------------------------------------------

// Appends the wire form of one entry of a container. wire holds the wire
// bytes of the value, and e.vlen its logical length for the prefix.
fn encode_entry(d: Dialect&, mode: i64, cont: i64, e: Entry, wire: const u8[:], out: u8[>..]&) -> i64 {
    let spec = d.subs[e.sub];
    if mode == COMPOSITE_BER {
        let f = ber_write_tag(out, e.tag);
        if f != OK { return f; }
        let g = ber_write_len(out, wire.len);
        if g != OK { return g; }
        out.append(wire);
        return OK;
    }
    if mode == COMPOSITE_TAGGED {
        let cs = container_spec(d, cont);
        var text: u8[>..] = [];
        format_int(text, e.tag, 10, cs.tag_width, '0');
        out.append(text);
    }
    if spec.kind != KIND_FIXED {
        let units = units_of(spec.enc, spec.unit, e.vlen);
        if units < 0 { return ERR_VALUE_LENGTH; }
        let f = put_prefix(out, spec.prefix_enc, spec.kind, units, d.page);
        if f != OK { return f; }
    }
    if uses_pad_char(spec) {
        pad_text(out, wire, spec.max_len, spec.padding, spec.pad_char as u8);
        return OK;
    }
    out.append(wire);
    return OK;
}

// Rebuilds the payload of a container. The entry at changed takes the
// wire bytes in wire and the logical length vlen, and keeps its place,
// so the wire order holds. changed -1 drops nothing, and drop -1 keeps
// every entry. The entry at drop leaves. An extra entry goes last when
// extra is not null.
fn rebuild(d: Dialect&, mode: i64, lvl: Level&, buf: const u8[:], changed: i64, drop: i64, extra: Entry, add: bool, wire: const u8[:], vlen: i64, out: u8[>..]&) -> i64 {
    out.clear();
    for k in 0..lvl.count {
        if k == drop { continue; }
        var e = lvl.ents[k];
        if k == changed {
            e.vlen = vlen;
            let f = encode_entry(d, mode, lvl.cont, e, wire, out);
            if f != OK { return f; }
        } else {
            if e.off < 0 || e.len < 0 || e.off + e.len > buf.len { return ERR_BAD_ARG; }
            let f = encode_entry(d, mode, lvl.cont, e, buf[e.off..e.off + e.len], out);
            if f != OK { return f; }
        }
        if out.len > MAX_FIELD { return ERR_VALUE_LENGTH; }
    }
    if add {
        var e = extra;
        e.vlen = vlen;
        let f = encode_entry(d, mode, lvl.cont, e, wire, out);
        if f != OK { return f; }
        if out.len > MAX_FIELD { return ERR_VALUE_LENGTH; }
    }
    return OK;
}

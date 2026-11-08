namespace iso8583;

import std;

// Appends the PAN mask of the digits in v. For n bytes the mask shows
// shown = min(10, max(0, n - 6)) of them: the last min(4, shown) and the
// first shown - last. Every other byte, and every byte that is not a
// digit, becomes '*'.
fn mask_pan(out: u8[>..]&, v: const u8[:]) {
    let n = v.len;
    var shown = n - 6;
    if shown < 0 { shown = 0; }
    if shown > 10 { shown = 10; }
    var last = shown;
    if last > 4 { last = 4; }
    let first = shown - last;
    for i in 0..n {
        if (i < first || i >= n - last) && is_digit(v[i]) {
            out.push(v[i]);
        } else {
            out.push('*');
        }
    }
}

// Appends a value for a log line. A byte that is not printable ASCII
// becomes '.', so a value cannot forge a log line. Raw binary data
// shows as hex.
fn text_value(out: u8[>..]&, enc: i64, v: const u8[:]) {
    if enc == ENC_BINARY {
        for i in 0..v.len {
            out.push(hex_char(v[i] >> 4));
            out.push(hex_char(v[i] & 15));
        }
        return;
    }
    for i in 0..v.len {
        if v[i] >= 32 && v[i] < 127 {
            out.push(v[i]);
        } else {
            out.push('.');
        }
    }
}

// Appends a tag for the text form. A BER tag shows as upper-case hex, a
// tagged-container tag as its digits, and a list position as a number.
fn text_tag(out: u8[>..]&, mode: i64, width: i64, tag: i64) {
    if mode == COMPOSITE_BER {
        var k = ber_tag_len(tag);
        if k < 1 { k = 1; }
        for i in 0..k {
            let b = (tag >> (8 * (k - 1 - i))) & 255;
            out.push(hex_char(b >> 4));
            out.push(hex_char(b & 15));
        }
    } else if mode == COMPOSITE_TAGGED {
        format_int(out, tag, 10, width, '0');
    } else {
        format_int(out, tag, 10, 0, ' ');
    }
}

// Appends the value of a leaf subfield under a mask mode.
fn text_leaf(out: u8[>..]&, d: Dialect&, spec: FieldSpec, mode: i64, wire: const u8[:], vlen: i64) {
    var v: u8[>..] = [];
    if decode_field_value(v, spec, wire, vlen, d.page) != OK {
        format(out, "*");
        return;
    }
    if mode == MASK_PAN {
        mask_pan(out, v);
    } else if mode == MASK_NONE {
        text_value(out, spec.enc, v);
    } else {
        for i in 0..v.len { out.push('*'); }
    }
}

// Appends one line for each subfield of the composite field fid. The walk
// uses a stack of three levels and no recursion. A subfield mask of
// MASK_INHERIT takes the mode of the nearest container that sets one.
// A payload that does not parse adds no line.
fn text_subs(out: u8[>..]&, d: Dialect&, fid: i64, payload: const u8[:]) {
    var st: Level[3] = [Level { .. }, Level { .. }, Level { .. }];
    var idx: i64[3] = [0, 0, 0];
    var base: i64[3] = [0, 0, 0];
    var inh: i64[3] = [MASK_FULL, MASK_FULL, MASK_FULL];
    var tags: i64[3] = [0, 0, 0];
    var modes: i64[3] = [0, 0, 0];
    var widths: i64[3] = [0, 0, 0];
    let top = d.fields[fid];
    var n, f = parse_level(d, fid, top.composite, payload, 0, payload.len, st[0]);
    if f != OK { return; }
    inh[0] = top.mask;
    if inh[0] == MASK_INHERIT { inh[0] = MASK_FULL; }
    modes[0] = top.composite;
    widths[0] = top.tag_width;
    var depth = 0;
    while depth >= 0 {
        if idx[depth] >= st[depth].count {
            depth -= 1;
            continue;
        }
        let e = st[depth].ents[idx[depth]];
        idx[depth] += 1;
        tags[depth] = e.tag;
        let spec = d.subs[e.sub];
        var mode = spec.mask;
        if mode == MASK_INHERIT { mode = inh[depth]; }
        format(out, "F");
        format_int(out, fid, 10, 3, '0');
        for k in 0..(depth + 1) {
            format(out, ".");
            text_tag(out, modes[k], widths[k], tags[k]);
        }
        format(out, " [");
        format_int(out, e.vlen, 10, 0, ' ');
        format(out, "] ");
        let at = base[depth] + e.off;
        if at < 0 || e.len < 0 || at + e.len > payload.len {
            format(out, "*\n");
            continue;
        }
        if spec.composite == COMPOSITE_NONE {
            text_leaf(out, d, spec, mode, payload[at..at + e.len], e.vlen);
            format(out, "\n");
            continue;
        }
        // A nested container shows no value. Its subfields show below.
        for i in 0..e.len { out.push('*'); }
        format(out, "\n");
        if depth >= 2 { continue; }
        var n2, f2 = parse_level(d, 1000 + e.sub, spec.composite, payload[at..at + e.len], 0, e.len, st[depth + 1]);
        if f2 != OK { continue; }
        depth += 1;
        idx[depth] = 0;
        base[depth] = at;
        inh[depth] = mode;
        modes[depth] = spec.composite;
        widths[depth] = spec.tag_width;
    }
}

// Appends the text form of a message: one line for the MTI, one line for
// each field. The mask mode of each field decides what shows. A composite
// field shows as one fully masked line and one line for each subfield.
fn message_text(out: u8[>..]&, msg: Message&, d: Dialect&) -> i64 {
    out.clear();
    format(out, "MTI ");
    text_value(out, ENC_ASCII, msg.mti);
    format(out, "\n");
    for id in 2..193 {
        if !msg.slots[id].present { continue; }
        let s = msg.slots[id];
        if s.off < 0 || s.len < 0 || s.off + s.len > msg.data.len {
            out.clear();
            return ERR_BAD_ARG;
        }
        let v = msg.data[s.off..s.off + s.len];
        var mode = MASK_FULL;
        var enc = ENC_ASCII;
        var composite = false;
        if d.fields[id].defined {
            mode = d.fields[id].mask;
            enc = d.fields[id].enc;
            // The subfield lines carry the values, each under its own mask.
            if d.fields[id].composite != COMPOSITE_NONE {
                mode = MASK_FULL;
                composite = true;
            }
        }
        format(out, "F");
        format_int(out, id, 10, 3, '0');
        format(out, " [");
        format_int(out, v.len, 10, 0, ' ');
        format(out, "] ");
        if mode == MASK_PAN {
            mask_pan(out, v);
        } else if mode == MASK_FULL {
            for i in 0..v.len { out.push('*'); }
        } else {
            text_value(out, enc, v);
        }
        format(out, "\n");
        if composite { text_subs(out, d, id, v); }
    }
    return OK;
}

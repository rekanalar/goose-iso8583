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

// Appends the text form of a message: one line for the MTI, one line for
// each field. The mask mode of each field decides what shows.
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
        if d.fields[id].defined {
            mode = d.fields[id].mask;
            enc = d.fields[id].enc;
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
    }
    return OK;
}

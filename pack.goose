namespace iso8583;

import std;

fn write_bitmap(out: u8[>..]&, w: u64, enc: i64, page: i64) {
    if enc == BITMAP_BINARY {
        for i in 0..8 { out.push((w >> ((56 - i * 8) as u64)) as u8); }
        return;
    }
    var text: u8[>..] = [];
    for i in 0..16 { text.push(hex_char(((w >> ((60 - i * 4) as u64)) & 15) as i64)); }
    if enc == BITMAP_HEX_EBCDIC {
        encode_value(out, ENC_EBCDIC, PAD_LEFT, 0, text, page);
    } else {
        out.append(text);
    }
}

// Packs a message under the dialect. The call checks every field against
// the dialect it receives. Field 1 and field 65 come from the fields that
// are present. out is empty on a fault, and msg.fault_field names the field.
fn pack(out: u8[>..]&, msg: Message&, d: Dialect&) -> i64 {
    out.clear();
    msg.fault_field = 0;
    if !mti_ok(msg.mti) { return ERR_BAD_MTI; }
    // Check every field before any byte is written.
    var b1: u64 = 0;
    var b2: u64 = 0;
    var b3: u64 = 0;
    for id in 2..193 {
        if !msg.slots[id].present { continue; }
        let s = msg.slots[id];
        if s.off < 0 || s.len < 0 || s.off + s.len > msg.data.len {
            msg.fault_field = id;
            return ERR_BAD_ARG;
        }
        let f = check_value(d, id, msg.data[s.off..s.off + s.len]);
        if f != OK {
            msg.fault_field = id;
            return f;
        }
        if id <= 64 {
            b1 = b1 | ((1 as u64) << ((64 - id) as u64));
        } else if id <= 128 {
            b2 = b2 | ((1 as u64) << ((128 - id) as u64));
        } else {
            b3 = b3 | ((1 as u64) << ((192 - id) as u64));
        }
    }
    let need_b3 = b3 != 0;
    let need_b2 = need_b3 || b2 != 0;
    if need_b3 { b2 = b2 | ((1 as u64) << 63); }
    if need_b2 { b1 = b1 | ((1 as u64) << 63); }
    // The MTI.
    encode_value(out, d.mti_enc, PAD_LEFT, 0, msg.mti, d.page);
    write_bitmap(out, b1, d.bitmap_enc, d.page);
    if need_b2 { write_bitmap(out, b2, d.bitmap_enc, d.page); }
    if need_b3 { write_bitmap(out, b3, d.bitmap_enc, d.page); }
    for id in 2..193 {
        if !msg.slots[id].present { continue; }
        let s = msg.slots[id];
        let spec = d.fields[id];
        let v = msg.data[s.off..s.off + s.len];
        let units = units_of(spec.enc, spec.unit, v.len);
        let f = put_prefix(out, spec.prefix_enc, spec.kind, units, d.page);
        if f != OK {
            out.clear();
            msg.fault_field = id;
            return f;
        }
        if uses_pad_char(spec) {
            var padded: u8[>..] = [];
            pad_text(padded, v, spec.max_len, spec.padding, spec.pad_char as u8);
            encode_value(out, spec.enc, spec.padding, spec.pad_digit, padded, d.page);
        } else {
            encode_value(out, spec.enc, spec.padding, spec.pad_digit, v, d.page);
        }
        if out.len > MAX_INPUT {
            out.clear();
            msg.fault_field = id;
            return ERR_TOO_LONG;
        }
    }
    return OK;
}

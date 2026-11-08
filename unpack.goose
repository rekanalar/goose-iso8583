namespace iso8583;

import std;

// Empties the message and records the field of the fault.
fn unpack_fail(msg: Message&, code: i64, field: i64) -> i64 {
    message_clear(msg);
    msg.fault_field = field;
    return code;
}

// Reads one bitmap. Returns the 64 bits, the new position and a fault code.
fn read_bitmap(input: const u8[:], pos: i64, enc: i64) -> u64, i64, i64 {
    var w: u64 = 0;
    if enc == BITMAP_BINARY {
        if pos + 8 > input.len { return 0, pos, ERR_TRUNCATED; }
        for i in 0..8 { w = (w << 8) | input[pos + i]; }
        return w, pos + 8, OK;
    }
    if pos + 16 > input.len { return 0, pos, ERR_TRUNCATED; }
    for i in 0..16 {
        var c = input[pos + i];
        if enc == BITMAP_HEX_EBCDIC {
            let a = EBCDIC_TO_ASCII[c];
            if a == 0 { return 0, pos, ERR_BAD_BYTE; }
            c = a;
        }
        let v = hex_value(c);
        if v < 0 { return 0, pos, ERR_BAD_BYTE; }
        w = (w << 4) | (v as u64);
    }
    return w, pos + 16, OK;
}

// True when bit n (1 to 64, counted from the left) is set.
fn bit_set(w: u64, n: i64) -> bool {
    if n < 1 || n > 64 { return false; }
    return ((w >> ((64 - n) as u64)) & 1) == 1;
}

// Reads the MTI. Returns the new position and a fault code.
fn read_mti(msg: Message&, d: Dialect&, input: const u8[:]) -> i64, i64 {
    var tmp: u8[>..] = [];
    if d.mti_enc == ENC_BCD {
        if input.len < 2 { return 0, ERR_TRUNCATED; }
        let f = decode_value(tmp, ENC_BCD, PAD_LEFT, input[0..2], 4);
        if f != OK { return 0, ERR_BAD_MTI; }
        msg.mti.append(tmp);
        return 2, OK;
    }
    if input.len < 4 { return 0, ERR_TRUNCATED; }
    let f = decode_value(tmp, d.mti_enc, PAD_LEFT, input[0..4], 4);
    if f != OK { return 0, ERR_BAD_MTI; }
    if !mti_ok(tmp) { return 0, ERR_BAD_MTI; }
    msg.mti.append(tmp);
    return 4, OK;
}

// Reads one field at pos. Returns the new position and a fault code.
fn read_field(msg: Message&, d: Dialect&, input: const u8[:], pos: i64, id: i64) -> i64, i64 {
    if !d.fields[id].defined { return pos, ERR_UNKNOWN_FIELD; }
    let spec = d.fields[id];
    var units = spec.max_len;
    if spec.kind != KIND_FIXED {
        let n, f = get_prefix(input, pos, spec.prefix_enc, spec.kind);
        if f != OK { return pos, f; }
        units = n;
    }
    if units > spec.max_len { return pos, ERR_BAD_LENGTH; }
    let vlen = value_len(spec.enc, spec.unit, units);
    let wire = wire_size(spec.enc, vlen);
    let start = pos + prefix_width(spec.prefix_enc, spec.kind);
    if start + wire > input.len { return pos, ERR_TRUNCATED; }
    if msg.data.len + vlen > MAX_INPUT { return pos, ERR_FULL; }
    let off = msg.data.len;
    let f = decode_value(msg.data, spec.enc, spec.padding, input[start..start + wire], vlen);
    if f != OK { return pos, f; }
    msg.slots[id] = Slot { present: true, off: off, len: vlen };
    return start + wire, OK;
}

// Unpacks input under the dialect. On a fault the message is empty and
// msg.fault_field names the field (0 for the MTI, the bitmaps and the
// input as a whole).
fn unpack(msg: Message&, d: Dialect&, input: const u8[:]) -> i64 {
    message_clear(msg);
    if input.len > MAX_INPUT { return unpack_fail(msg, ERR_TOO_LONG, 0); }
    let p0, f0 = read_mti(msg, d, input);
    if f0 != OK { return unpack_fail(msg, f0, 0); }
    var pos = p0;
    let b1, p1, f1 = read_bitmap(input, pos, d.bitmap_enc);
    if f1 != OK { return unpack_fail(msg, f1, 0); }
    pos = p1;
    var b2: u64 = 0;
    var b3: u64 = 0;
    if bit_set(b1, 1) {
        let w2, p2, f2 = read_bitmap(input, pos, d.bitmap_enc);
        if f2 != OK { return unpack_fail(msg, f2, 0); }
        b2 = w2;
        pos = p2;
        if bit_set(b2, 1) {
            if d.bitmaps < 3 { return unpack_fail(msg, ERR_BAD_BITMAP, 65); }
            let w3, p3, f3 = read_bitmap(input, pos, d.bitmap_enc);
            if f3 != OK { return unpack_fail(msg, f3, 0); }
            b3 = w3;
            pos = p3;
        }
    }
    for id in 2..193 {
        if id == 65 { continue; }
        var set = false;
        if id <= 64 {
            set = bit_set(b1, id);
        } else if id <= 128 {
            set = bit_set(b2, id - 64);
        } else {
            set = bit_set(b3, id - 128);
        }
        if !set { continue; }
        let np, f = read_field(msg, d, input, pos, id);
        if f != OK { return unpack_fail(msg, f, id); }
        pos = np;
    }
    if pos != input.len { return unpack_fail(msg, ERR_TRAILING, 0); }
    return OK;
}

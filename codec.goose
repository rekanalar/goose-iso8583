namespace iso8583;

import std;

// ---- sizes -----------------------------------------------------------

fn is_nibble_enc(enc: i64) -> bool {
    return enc == ENC_BCD || enc == ENC_HEX;
}

// Wire bytes of a value with vlen characters, digits or bytes.
fn wire_size(enc: i64, vlen: i64) -> i64 {
    if is_nibble_enc(enc) { return (vlen + 1) / 2; }
    return vlen;
}

// Length of the value for a count in the unit of the field.
fn value_len(enc: i64, unit: i64, units: i64) -> i64 {
    if is_nibble_enc(enc) && unit == UNIT_BYTES { return units * 2; }
    return units;
}

// The count in the unit of the field for a value length, or -1 when the
// length cannot be written in that unit.
fn units_of(enc: i64, unit: i64, vlen: i64) -> i64 {
    if is_nibble_enc(enc) && unit == UNIT_BYTES {
        if vlen % 2 != 0 { return -1; }
        return vlen / 2;
    }
    return vlen;
}

// ---- alphabets -------------------------------------------------------

// OK when every byte of v is in the alphabet of the encoding.
fn check_alphabet(enc: i64, v: const u8[:]) -> i64 {
    for i in 0..v.len {
        let c = v[i];
        if enc == ENC_ASCII || enc == ENC_EBCDIC {
            if c > 127 { return ERR_BAD_BYTE; }
        } else if enc == ENC_BCD {
            if !is_digit(c) { return ERR_BAD_BYTE; }
        } else if enc == ENC_HEX {
            if hex_value(c) < 0 { return ERR_BAD_BYTE; }
        }
    }
    return OK;
}

// ---- values ----------------------------------------------------------

// Appends the wire form of v. The caller checked the alphabet.
fn encode_value(out: u8[>..]&, enc: i64, padding: i64, v: const u8[:]) {
    if enc == ENC_ASCII || enc == ENC_BINARY {
        out.append(v);
    } else if enc == ENC_EBCDIC {
        for i in 0..v.len { out.push(ASCII_TO_EBCDIC[v[i] % 128]); }
    } else {
        let n = v.len;
        let odd = n % 2 == 1;
        var total = n;
        if odd { total = n + 1; }
        var cur: u8 = 0;
        for k in 0..total {
            var nib: i64 = 0;
            if odd && padding == PAD_LEFT {
                if k > 0 { nib = hex_value(v[k - 1]); }
            } else if k < n {
                nib = hex_value(v[k]);
            }
            if nib < 0 { nib = 0; }
            if k % 2 == 0 {
                cur = (nib as u8) << 4;
            } else {
                out.push(cur | (nib as u8));
            }
        }
    }
}

// Appends the value held in the wire bytes w. w.len must equal
// wire_size(enc, vlen). A byte outside the alphabet and a bad padding nibble
// give ERR_BAD_BYTE.
fn decode_value(out: u8[>..]&, enc: i64, padding: i64, w: const u8[:], vlen: i64) -> i64 {
    if w.len != wire_size(enc, vlen) { return ERR_TRUNCATED; }
    if enc == ENC_BINARY {
        out.append(w);
        return OK;
    }
    if enc == ENC_ASCII {
        for i in 0..w.len {
            if w[i] > 127 { return ERR_BAD_BYTE; }
            out.push(w[i]);
        }
        return OK;
    }
    if enc == ENC_EBCDIC {
        for i in 0..w.len {
            let a = EBCDIC_TO_ASCII[w[i]];
            if a == 0 && w[i] != 0 { return ERR_BAD_BYTE; }
            out.push(a);
        }
        return OK;
    }
    let odd = vlen % 2 == 1;
    let nibbles = w.len * 2;
    for k in 0..nibbles {
        var nib: i64 = w[k / 2] >> 4;
        if k % 2 == 1 { nib = w[k / 2] & 15; }
        var is_pad = false;
        if odd && padding == PAD_LEFT && k == 0 { is_pad = true; }
        if odd && padding == PAD_RIGHT && k == nibbles - 1 { is_pad = true; }
        if is_pad {
            if nib != 0 { return ERR_BAD_BYTE; }
        } else if enc == ENC_BCD {
            if nib > 9 { return ERR_BAD_BYTE; }
            out.push('0' + (nib as u8));
        } else {
            out.push(hex_char(nib));
        }
    }
    return OK;
}

// ---- length prefixes --------------------------------------------------

// Width of the prefix in wire bytes. 0 for a fixed field.
fn prefix_width(prefix_enc: i64, kind: i64) -> i64 {
    if kind == KIND_FIXED { return 0; }
    if prefix_enc == ENC_ASCII || prefix_enc == ENC_EBCDIC {
        if kind == KIND_LLVAR { return 2; }
        return 3;
    }
    if kind == KIND_LLVAR { return 1; }
    return 2;
}

// Largest count that the prefix can hold and the package allows.
fn prefix_cap(prefix_enc: i64, kind: i64) -> i64 {
    if kind == KIND_FIXED { return MAX_FIELD; }
    if prefix_enc == ENC_BINARY && kind == KIND_LLVAR { return 255; }
    if kind == KIND_LLVAR { return 99; }
    return 999;
}

// Appends the prefix for a count. ERR_BAD_LENGTH when it does not fit.
fn put_prefix(out: u8[>..]&, prefix_enc: i64, kind: i64, units: i64) -> i64 {
    if kind == KIND_FIXED { return OK; }
    if units < 0 || units > prefix_cap(prefix_enc, kind) { return ERR_BAD_LENGTH; }
    let w = prefix_width(prefix_enc, kind);
    if prefix_enc == ENC_BINARY {
        if w == 2 { out.push((units / 256) as u8); }
        out.push((units % 256) as u8);
        return OK;
    }
    var digits: i64 = w;
    if prefix_enc == ENC_BCD { digits = w * 2; }
    var text: u8[>..] = [];
    format_int(text, units, 10, digits, '0');
    encode_value(out, prefix_enc, PAD_LEFT, text);
    return OK;
}

// Reads the prefix at pos. Returns the count and a fault code. A prefix
// that is not a number gives ERR_BAD_LENGTH.
fn get_prefix(input: const u8[:], pos: i64, prefix_enc: i64, kind: i64) -> i64, i64 {
    if kind == KIND_FIXED { return 0, OK; }
    let w = prefix_width(prefix_enc, kind);
    if pos < 0 || pos + w > input.len { return 0, ERR_TRUNCATED; }
    var n: i64 = 0;
    if prefix_enc == ENC_BINARY {
        for i in 0..w { n = n * 256 + input[pos + i]; }
        return n, OK;
    }
    if prefix_enc == ENC_BCD {
        for i in 0..w {
            let hi = (input[pos + i] >> 4) as i64;
            let lo = (input[pos + i] & 15) as i64;
            if hi > 9 || lo > 9 { return 0, ERR_BAD_LENGTH; }
            n = n * 100 + hi * 10 + lo;
        }
        return n, OK;
    }
    for i in 0..w {
        var c = input[pos + i];
        if prefix_enc == ENC_EBCDIC {
            let a = EBCDIC_TO_ASCII[c];
            if a == 0 { return 0, ERR_BAD_LENGTH; }
            c = a;
        }
        if !is_digit(c) { return 0, ERR_BAD_LENGTH; }
        n = n * 10 + (c - '0');
    }
    return n, OK;
}

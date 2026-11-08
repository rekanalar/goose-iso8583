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
fn check_alphabet(enc: i64, v: const u8[:]) -> i64 {  // page unused; the alphabet is the ASCII set
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
fn encode_value(out: u8[>..]&, enc: i64, padding: i64, pad_digit: i64, v: const u8[:], page: i64) {
    if enc == ENC_ASCII || enc == ENC_BINARY {
        out.append(v);
    } else if enc == ENC_EBCDIC {
        for i in 0..v.len { out.push(ASCII_TO_EBCDIC[page * 256 + (v[i] % 128)]); }
    } else {
        let n = v.len;
        let odd = n % 2 == 1;
        var total = n;
        if odd { total = n + 1; }
        var cur: u8 = 0;
        for k in 0..total {
            var nib: i64 = 0;
            var is_pad = false;
            if odd && padding == PAD_LEFT {
                if k == 0 { is_pad = true; } else { nib = hex_value(v[k - 1]); }
            } else if odd && padding == PAD_RIGHT {
                if k == n { is_pad = true; } else { nib = hex_value(v[k]); }
            } else if k < n {
                nib = hex_value(v[k]);
            }
            if is_pad || nib < 0 { nib = pad_digit; }
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
fn decode_value(out: u8[>..]&, enc: i64, padding: i64, pad_digit: i64, w: const u8[:], vlen: i64, page: i64) -> i64 {
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
            let a = EBCDIC_TO_ASCII[page * 256 + w[i]];
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
            if nib != pad_digit { return ERR_BAD_BYTE; }
        } else if enc == ENC_BCD {
            if nib > 9 { return ERR_BAD_BYTE; }
            out.push('0' + (nib as u8));
        } else {
            out.push(hex_char(nib));
        }
    }
    return OK;
}

// ---- pad characters ---------------------------------------------------

// Appends the value to out and fills the rest of a fixed length with
// the pad character. side is PAD_LEFT or PAD_RIGHT. len is the full
// length in characters. The caller checked that the value fits.
fn pad_text(out: u8[>..]&, v: const u8[:], len: i64, side: i64, ch: u8) {
    let fill = len - v.len;
    if side == PAD_LEFT {
        for i in 0..fill { out.push(ch); }
        out.append(v);
        return;
    }
    out.append(v);
    for i in 0..fill { out.push(ch); }
}

// Removes the run of pad characters on the side of a decoded value, in
// place. A value that is all pad characters becomes empty.
fn strip_pad_char(v: u8[>..]&, side: i64, ch: u8) {
    if side == PAD_LEFT {
        var start = 0;
        while start < v.len && v[start] == ch { start += 1; }
        if start > 0 {
            var rest: u8[>..] = [];
            rest.append(v[start..v.len]);
            v.clear();
            v.append(rest);
        }
        return;
    }
    var end = v.len;
    while end > 0 && v[end - 1] == ch { end -= 1; }
    if end < v.len {
        var rest: u8[>..] = [];
        rest.append(v[0..end]);
        v.clear();
        v.append(rest);
    }
}

// True when a value that could not round trip: a left pad value must not
// start with the pad character, and a right pad value must not end with
// it.
fn pad_unsafe(v: const u8[:], side: i64, ch: u8) -> bool {
    if v.len == 0 { return false; }
    if side == PAD_LEFT { return v[0] == ch; }
    return v[v.len - 1] == ch;
}

// True when the spec pads a fixed text field with a pad character.
fn uses_pad_char(spec: FieldSpec) -> bool {
    if spec.pad_char < 0 { return false; }
    if spec.kind != KIND_FIXED { return false; }
    return spec.enc == ENC_ASCII || spec.enc == ENC_EBCDIC;
}

// Decodes the wire bytes of a value and removes the pad characters. The
// logical value of a padded field is shorter than its wire form.
fn decode_field_value(out: u8[>..]&, spec: FieldSpec, wire: const u8[:], vlen: i64, page: i64) -> i64 {
    let f = decode_value(out, spec.enc, spec.padding, spec.pad_digit, wire, vlen, page);
    if f != OK { return f; }
    if uses_pad_char(spec) { strip_pad_char(out, spec.padding, spec.pad_char as u8); }
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

// Largest count that a count field of width w bytes can hold in enc.
fn count_cap(enc: i64, w: i64) -> i64 {
    if enc == ENC_BINARY {
        var n: i64 = 1;
        for i in 0..w { n = n * 256; }
        return n - 1;
    }
    var digits: i64 = w;
    if enc == ENC_BCD { digits = w * 2; }
    var n: i64 = 1;
    for i in 0..digits { n = n * 10; }
    return n - 1;
}

// Appends the count n in enc at width w wire bytes. Counts as ASCII or
// EBCDIC digits, BCD digit pairs, or big-endian binary bytes.
// ERR_BAD_LENGTH when n does not fit the width.
fn put_count(out: u8[>..]&, enc: i64, w: i64, n: i64, page: i64) -> i64 {
    if w < 1 || w > 4 { return ERR_BAD_ARG; }
    if n < 0 || n > count_cap(enc, w) { return ERR_BAD_LENGTH; }
    if enc == ENC_BINARY {
        for i in 0..w {
            var shift: i64 = 8 * (w - 1 - i);
            var byte: i64 = (n >> shift) & 255;
            out.push(byte as u8);
        }
        return OK;
    }
    var digits: i64 = w;
    if enc == ENC_BCD { digits = w * 2; }
    var text: u8[>..] = [];
    format_int(text, n, 10, digits, '0');
    encode_value(out, enc, PAD_LEFT, 0, text, page);
    return OK;
}

// Reads the count in enc at width w wire bytes from pos. Returns the
// count and a fault code. A count that is not a number gives
// ERR_BAD_LENGTH.
fn get_count(input: const u8[:], pos: i64, enc: i64, w: i64, page: i64) -> i64, i64 {
    if w < 1 || w > 4 { return 0, ERR_BAD_ARG; }
    if pos < 0 || pos + w > input.len { return 0, ERR_TRUNCATED; }
    var n: i64 = 0;
    if enc == ENC_BINARY {
        for i in 0..w { n = n * 256 + input[pos + i]; }
        return n, OK;
    }
    if enc == ENC_BCD {
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
        if enc == ENC_EBCDIC {
            let a = EBCDIC_TO_ASCII[page * 256 + c];
            if a == 0 { return 0, ERR_BAD_LENGTH; }
            c = a;
        }
        if !is_digit(c) { return 0, ERR_BAD_LENGTH; }
        n = n * 10 + (c - '0');
    }
    return n, OK;
}

// Appends the prefix for a count. ERR_BAD_LENGTH when it does not fit.
fn put_prefix(out: u8[>..]&, prefix_enc: i64, kind: i64, units: i64, page: i64) -> i64 {
    if kind == KIND_FIXED { return OK; }
    if units < 0 || units > prefix_cap(prefix_enc, kind) { return ERR_BAD_LENGTH; }
    return put_count(out, prefix_enc, prefix_width(prefix_enc, kind), units, page);
}

// Reads the prefix at pos. Returns the count and a fault code. A prefix
// that is not a number gives ERR_BAD_LENGTH.
fn get_prefix(input: const u8[:], pos: i64, prefix_enc: i64, kind: i64, page: i64) -> i64, i64 {
    if kind == KIND_FIXED { return 0, OK; }
    return get_count(input, pos, prefix_enc, prefix_width(prefix_enc, kind), page);
}

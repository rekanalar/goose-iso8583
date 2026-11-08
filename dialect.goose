namespace iso8583;

import std;

// Clears d and sets its framing. mti_enc is ENC_ASCII, ENC_EBCDIC or
// ENC_BCD. bitmap_enc is a BITMAP_* value. bitmaps is 2, or 3 for a
// dialect with a tertiary bitmap and the fields 129 to 192. d stays
// unchanged when an argument is bad.
fn dialect_init(d: Dialect&, mti_enc: i64, bitmap_enc: i64, bitmaps: i64) -> i64 {
    if mti_enc != ENC_ASCII && mti_enc != ENC_EBCDIC && mti_enc != ENC_BCD { return ERR_BAD_ARG; }
    if bitmap_enc < BITMAP_BINARY || bitmap_enc > BITMAP_HEX_EBCDIC { return ERR_BAD_ARG; }
    if bitmaps != 2 && bitmaps != 3 { return ERR_BAD_ARG; }
    d.mti_enc = mti_enc;
    d.bitmap_enc = bitmap_enc;
    d.bitmaps = bitmaps;
    for i in 0..193 { d.fields[i] = FieldSpec { .. }; }
    return OK;
}

// Defines the field id. Field 1 and field 65 belong to the package. The
// call checks every argument and leaves d unchanged on a fault.
fn dialect_field(d: Dialect&, id: i64, kind: i64, enc: i64, prefix_enc: i64, unit: i64, max_len: i64, padding: i64, mask: i64) -> i64 {
    if !valid_id(id) { return ERR_BAD_FIELD_ID; }
    if id > 128 && d.bitmaps < 3 { return ERR_BAD_FIELD_ID; }
    if kind < KIND_FIXED || kind > KIND_LLLVAR { return ERR_BAD_ARG; }
    if enc < ENC_ASCII || enc > ENC_HEX { return ERR_BAD_ARG; }
    if unit != UNIT_BYTES && unit != UNIT_NIBBLES { return ERR_BAD_ARG; }
    if padding != PAD_LEFT && padding != PAD_RIGHT { return ERR_BAD_ARG; }
    if mask < MASK_NONE || mask > MASK_FULL { return ERR_BAD_ARG; }
    if kind != KIND_FIXED {
        if prefix_enc != ENC_ASCII && prefix_enc != ENC_EBCDIC && prefix_enc != ENC_BCD && prefix_enc != ENC_BINARY { return ERR_BAD_ARG; }
    }
    if unit == UNIT_NIBBLES && !is_nibble_enc(enc) { return ERR_BAD_ARG; }
    if max_len < 1 || max_len > prefix_cap(prefix_enc, kind) { return ERR_BAD_ARG; }
    d.fields[id] = FieldSpec {
        defined: true, kind: kind, enc: enc, prefix_enc: prefix_enc,
        unit: unit, max_len: max_len, padding: padding, mask: mask,
    };
    return OK;
}

// True when the field is defined in the dialect.
fn dialect_has(d: Dialect&, id: i64) -> bool {
    if !valid_id(id) { return false; }
    return d.fields[id].defined;
}

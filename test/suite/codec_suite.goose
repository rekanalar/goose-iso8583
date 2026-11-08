namespace suite;

import std;
import iso8583 from "../..";
import util;

// Builds a dialect with ASCII MTI and binary bitmaps. Field 2 gets the
// description that the test gives.
fn one_field(d: iso8583::Dialect&, kind: i64, enc: i64, prefix: i64, unit: i64, max_len: i64, padding: i64) -> i64 {
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    return iso8583::dialect_field(d, 2, kind, enc, prefix, unit, max_len, padding, 0);
}

// Packs a message with the one value in field 2 and compares the bytes
// that follow the MTI and the bitmap with the expected hex. Then unpacks
// the bytes and compares the value.
fn wire_case(d: iso8583::Dialect&, value: const u8[:], want_hex: const u8[:], what: const u8[:]) -> i64 {
    var bad = 0;
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    let s = iso8583::message_set(m, d, 2, value);
    if s != iso8583::OK { print("FAIL: ", what, ": set gave ", s, "\n"); return 1; }
    var out: u8[>..] = [];
    bad += check(iso8583::pack(out, m, d) == iso8583::OK, what);
    var head: u8[>..] = [];
    from_hex(head, "303230304000000000000000");
    var tail: u8[>..] = [];
    from_hex(tail, want_hex);
    head.append(tail);
    bad += eq_bytes(out, head, what);
    var back = iso8583::Message { .. };
    bad += check(iso8583::unpack(back, d, out) == iso8583::OK, what);
    var got: u8[>..] = [];
    iso8583::message_get(back, 2, got);
    bad += eq_bytes(got, value, what);
    return bad;
}

fn run_codec() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    // BCD, count in nibbles, ASCII prefix: pad nibble on either side.
    one_field(d, iso8583::KIND_LLVAR, iso8583::ENC_BCD, iso8583::ENC_ASCII, iso8583::UNIT_NIBBLES, 19, iso8583::PAD_LEFT);
    bad += wire_case(d, "12345", "3035012345", "bcd odd pad left");
    bad += wire_case(d, "1234", "30341234", "bcd even");
    one_field(d, iso8583::KIND_LLVAR, iso8583::ENC_BCD, iso8583::ENC_ASCII, iso8583::UNIT_NIBBLES, 19, iso8583::PAD_RIGHT);
    bad += wire_case(d, "12345", "3035123450", "bcd odd pad right");
    // BCD, count in wire bytes.
    one_field(d, iso8583::KIND_LLVAR, iso8583::ENC_BCD, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 10, iso8583::PAD_LEFT);
    bad += wire_case(d, "123456", "3033123456", "bcd count in bytes");
    // Hex data.
    one_field(d, iso8583::KIND_FIXED, iso8583::ENC_HEX, 0, iso8583::UNIT_NIBBLES, 3, iso8583::PAD_LEFT);
    bad += wire_case(d, "ABC", "0ABC", "hex odd pad left");
    one_field(d, iso8583::KIND_FIXED, iso8583::ENC_HEX, 0, iso8583::UNIT_NIBBLES, 3, iso8583::PAD_RIGHT);
    bad += wire_case(d, "ABC", "ABC0", "hex odd pad right");
    // Binary data with a binary prefix of one and of two bytes.
    one_field(d, iso8583::KIND_LLVAR, iso8583::ENC_BINARY, iso8583::ENC_BINARY, iso8583::UNIT_BYTES, 200, iso8583::PAD_LEFT);
    var raw: u8[>..] = [];
    from_hex(raw, "00FF80");
    bad += wire_case(d, raw, "0300FF80", "binary prefix one byte");
    one_field(d, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_BINARY, iso8583::UNIT_BYTES, 300, iso8583::PAD_LEFT);
    bad += wire_case(d, raw, "000300FF80", "binary prefix two bytes");
    // BCD prefix of two bytes.
    one_field(d, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_BCD, iso8583::UNIT_BYTES, 300, iso8583::PAD_LEFT);
    bad += wire_case(d, "AB", "00024142", "bcd prefix two bytes");
    // EBCDIC prefix and data.
    one_field(d, iso8583::KIND_LLVAR, iso8583::ENC_EBCDIC, iso8583::ENC_EBCDIC, iso8583::UNIT_BYTES, 30, iso8583::PAD_LEFT);
    bad += wire_case(d, "A1 z", "F0F4C1F140A9", "ebcdic prefix and data");
    // A variable field of length zero.
    one_field(d, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 30, iso8583::PAD_LEFT);
    bad += wire_case(d, "", "3030", "zero length");
    return bad;
}

// The pad suite. It covers the pad digit of a BCD or hex value with an
// odd digit count and the pad character of a fixed text field.
namespace suite;

import std;
import iso8583 from "../..";
import util;

// A BCD field with an odd digit count and a pad digit of 15.
fn run_pad_digit() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(d, 2, iso8583::KIND_FIXED, iso8583::ENC_BCD, 0,
                           iso8583::UNIT_NIBBLES, 5, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(2), 15, -1) == iso8583::OK, "pad digit set");
    var m = iso8583::Message { .. };
    bad += check(iso8583::message_set_mti(m, "0200") == iso8583::OK, "mti");
    bad += check(iso8583::message_set(m, d, 2, "12345") == iso8583::OK, "set bcd value");
    var out: u8[>..] = [];
    bad += check(iso8583::pack(out, m, d) == iso8583::OK, "pack");
    // The MTI, the bitmap and three wire bytes.
    bad += check(out.len == 4 + 8 + 3, "wire length");
    bad += check(out[12] == 0xF1 && out[13] == 0x23 && out[14] == 0x45, "the pad nibble is on the wire");
    // The same bytes unpack to the same value.
    var m2 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m2, d, out) == iso8583::OK, "unpack");
    var got: u8[>..] = [];
    bad += check(iso8583::message_get(m2, 2, got) == iso8583::OK && same(got, "12345"), "value round trip");
    // Another pad nibble on the wire is a fault.
    var other: u8[>..] = [];
    other.append(out);
    other[12] = 0x01;
    var m3 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m3, d, other) == iso8583::ERR_BAD_BYTE, "another pad nibble faults");
    bad += check(m3.fault_field == 2, "the fault names the field");
    // The pad digit of a field with an even digit count has no place.
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(3), 15, -1) == iso8583::ERR_UNKNOWN_FIELD, "unknown field");
    return bad;
}

// A fixed text field with a pad character and a side.
fn run_pad_char() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(d, 3, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0,
                           iso8583::UNIT_BYTES, 6, iso8583::PAD_RIGHT, iso8583::MASK_NONE);
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(3), 0, 0x20) == iso8583::OK, "pad char set");
    var m = iso8583::Message { .. };
    bad += check(iso8583::message_set_mti(m, "0200") == iso8583::OK, "mti");
    // A short value is allowed and the pad fills the field.
    bad += check(iso8583::message_set(m, d, 3, "AB") == iso8583::OK, "short value");
    var out: u8[>..] = [];
    bad += check(iso8583::pack(out, m, d) == iso8583::OK, "pack");
    bad += check(out.len == 4 + 8 + 6, "wire length");
    bad += check(same(out[12..18], "AB    "), "the pad character is on the wire");
    // The same bytes unpack to the value without the pad.
    var m2 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m2, d, out) == iso8583::OK, "unpack");
    var got: u8[>..] = [];
    bad += check(iso8583::message_get(m2, 3, got) == iso8583::OK && same(got, "AB"), "value without the pad");
    // A value that ends with the pad character cannot round trip.
    bad += check(iso8583::message_set(m, d, 3, "AB ") == iso8583::ERR_VALUE_LENGTH, "a value with the pad character is refused");
    // A field of pad characters alone unpacks to an empty value.
    var full: u8[>..] = [];
    full.append(out);
    for i in 0..6 { full[12 + i] = 0x20; }
    var m3 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m3, d, full) == iso8583::OK, "unpack of a padded field");
    got.clear();
    bad += check(iso8583::message_get(m3, 3, got) == iso8583::OK && got.len == 0, "a padded field gives an empty value");
    // The pad character on the left side works the same way.
    var e = iso8583::Dialect { .. };
    iso8583::dialect_init(e, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(e, 4, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0,
                           iso8583::UNIT_BYTES, 6, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    bad += check(iso8583::dialect_field_pad(e, iso8583::path1(4), 0, 0x2E) == iso8583::OK, "pad char on the left");
    var m4 = iso8583::Message { .. };
    iso8583::message_set_mti(m4, "0200");
    bad += check(iso8583::message_set(m4, e, 4, "AB") == iso8583::OK, "set a short value");
    bad += check(iso8583::message_set(m4, e, 4, ".AB") == iso8583::ERR_VALUE_LENGTH, "a value with the pad character is refused");
    var out2: u8[>..] = [];
    bad += check(iso8583::pack(out2, m4, e) == iso8583::OK, "pack left");
    bad += check(same(out2[12..18], "....AB"), "the pad character on the left");
    var m5 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m5, e, out2) == iso8583::OK, "unpack left");
    got.clear();
    bad += check(iso8583::message_get(m5, 4, got) == iso8583::OK && same(got, "AB"), "value without the left pad");
    bad += run_pad_sub();
    return bad;
}

// A subfield takes a pad character too. The container keeps the pad on
// the wire, and the logical value has no pad.
fn run_pad_sub() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    iso8583::dialect_field(d, 55, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII,
                           iso8583::UNIT_BYTES, 99, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_TAGGED, 2);
    iso8583::dialect_sub(d, iso8583::path1(55), 12, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0,
                         iso8583::UNIT_BYTES, 6, iso8583::PAD_RIGHT, iso8583::MASK_NONE);
    bad += check(iso8583::dialect_field_pad(d, iso8583::path2(55, 12), 0, 0x20) == iso8583::OK, "pad char on a subfield");
    var m = iso8583::Message { .. };
    bad += check(iso8583::message_set_mti(m, "0200") == iso8583::OK, "mti");
    bad += check(iso8583::message_set_sub(m, d, iso8583::path2(55, 12), "AB") == iso8583::OK, "a short subfield");
    var got: u8[>..] = [];
    bad += check(iso8583::message_get_sub(m, d, iso8583::path2(55, 12), got) == iso8583::OK, "get the subfield");
    bad += check(same(got, "AB"), "the subfield has no pad");
    // The container keeps the pad on the wire.
    var out: u8[>..] = [];
    bad += check(iso8583::pack(out, m, d) == iso8583::OK, "pack");
    var m2 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m2, d, out) == iso8583::OK, "unpack");
    got.clear();
    bad += check(iso8583::message_get_sub(m2, d, iso8583::path2(55, 12), got) == iso8583::OK && same(got, "AB"), "the subfield has no pad after a round trip");
    // A value that ends with the pad character cannot round trip.
    bad += check(iso8583::message_set_sub(m, d, iso8583::path2(55, 12), "AB ") == iso8583::ERR_VALUE_LENGTH, "a subfield with the pad character is refused");
    return bad;
}

// The dialect call checks its arguments.
fn run_pad_args() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(d, 2, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0,
                           iso8583::UNIT_BYTES, 6, iso8583::PAD_RIGHT, iso8583::MASK_NONE);
    iso8583::dialect_field(d, 3, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII,
                           iso8583::UNIT_BYTES, 20, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(2), 16, -1) == iso8583::ERR_BAD_ARG, "pad digit above 15");
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(2), -1, -1) == iso8583::ERR_BAD_ARG, "pad digit below zero");
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(2), 0, 0x7F) == iso8583::ERR_BAD_ARG, "pad char above the alphabet");
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(2), 0, 0x1F) == iso8583::ERR_BAD_ARG, "pad char below the alphabet");
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(3), 0, 0x20) == iso8583::ERR_BAD_ARG, "pad char on a variable field");
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(2), 5, -1) == iso8583::ERR_BAD_ARG, "pad digit on a text field");
    bad += check(iso8583::dialect_field_pad(d, iso8583::path1(9), 0, -1) == iso8583::ERR_UNKNOWN_FIELD, "pad on an unknown field");
    return bad;
}

fn run_pad() -> i64 {
    var bad = 0;
    bad += run_pad_digit();
    bad += run_pad_char();
    bad += run_pad_args();
    return bad;
}

namespace suite;

import std;
import iso8583 from "../..";
import util;

fn run_message() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    var m = iso8583::Message { .. };
    bad += check(iso8583::message_set_mti(m, "0200") == iso8583::OK, "mti");
    bad += check(iso8583::message_set_mti(m, "020") == iso8583::ERR_BAD_MTI, "short mti");
    bad += check(iso8583::message_set_mti(m, "02X0") == iso8583::ERR_BAD_MTI, "letter in mti");
    bad += check(iso8583::message_set_mti(m, "02000") == iso8583::ERR_BAD_MTI, "long mti");
    bad += check(eq_bytes(m.mti, "0200", "mti stays after a bad set") == 0, "mti kept");
    // Set, get, has, unset.
    bad += check(iso8583::message_set(m, d, 2, "4111111111111111") == iso8583::OK, "set 2");
    bad += check(iso8583::message_set(m, d, 3, "000000") == iso8583::OK, "set 3");
    bad += check(iso8583::message_set(m, d, 41, "TERM0001") == iso8583::OK, "set 41");
    var out: u8[>..] = [];
    bad += check(iso8583::message_get(m, 3, out) == iso8583::OK && same(out, "000000"), "get 3");
    bad += check(iso8583::message_has(m, 2) && !iso8583::message_has(m, 4), "has");
    bad += check(iso8583::message_get(m, 4, out) == iso8583::ERR_NOT_SET && out.len == 0, "get missing");
    bad += check(iso8583::message_unset(m, 3) == iso8583::OK && !iso8583::message_has(m, 3), "unset");
    bad += check(iso8583::message_unset(m, 3) == iso8583::ERR_NOT_SET, "unset twice");
    bad += check(iso8583::message_get(m, 2, out) == iso8583::OK && same(out, "4111111111111111"), "other fields survive an unset");
    bad += check(iso8583::message_get(m, 41, out) == iso8583::OK && same(out, "TERM0001"), "field after the hole survives");
    // A second set replaces the first.
    bad += check(iso8583::message_set(m, d, 2, "5500000000000004") == iso8583::OK, "replace 2");
    bad += check(iso8583::message_get(m, 2, out) == iso8583::OK && same(out, "5500000000000004"), "replaced value");
    // Set refuses a bad id, a bad length and a bad byte.
    bad += check(iso8583::message_set(m, d, 1, "x") == iso8583::ERR_BAD_FIELD_ID, "set 1");
    bad += check(iso8583::message_set(m, d, 65, "x") == iso8583::ERR_BAD_FIELD_ID, "set 65");
    bad += check(iso8583::message_set(m, d, 0, "x") == iso8583::ERR_BAD_FIELD_ID, "set 0");
    bad += check(iso8583::message_set(m, d, 193, "x") == iso8583::ERR_BAD_FIELD_ID, "set 193");
    bad += check(iso8583::message_set(m, d, -1, "x") == iso8583::ERR_BAD_FIELD_ID, "set -1");
    bad += check(iso8583::message_set(m, d, 129, "x") == iso8583::ERR_BAD_FIELD_ID || iso8583::message_set(m, d, 129, "x") == iso8583::ERR_UNKNOWN_FIELD, "set 129");
    bad += check(iso8583::message_set(m, d, 3, "12345") == iso8583::ERR_VALUE_LENGTH, "fixed field too short");
    bad += check(iso8583::message_set(m, d, 3, "1234567") == iso8583::ERR_VALUE_LENGTH, "fixed field too long");
    bad += check(iso8583::message_set(m, d, 2, "12345678901234567890") == iso8583::ERR_VALUE_LENGTH, "LLVAR too long");
    var hi: u8[>..] = [];
    from_hex(hi, "4180");
    bad += check(iso8583::message_set(m, d, 48, hi) == iso8583::ERR_BAD_BYTE, "byte above 127 in ASCII");
    bad += check(iso8583::message_get(m, 1, out) == iso8583::ERR_BAD_FIELD_ID, "get 1");
    bad += check(iso8583::message_unset(m, 300) == iso8583::ERR_BAD_FIELD_ID, "unset 300");
    // BCD takes digits only, hex takes upper-case hex only.
    var x = iso8583::Dialect { .. };
    iso8583::dialect_init(x, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(x, 2, iso8583::KIND_FIXED, iso8583::ENC_BCD, 0, iso8583::UNIT_NIBBLES, 4, iso8583::PAD_LEFT, 0);
    iso8583::dialect_field(x, 3, iso8583::KIND_FIXED, iso8583::ENC_HEX, 0, iso8583::UNIT_NIBBLES, 4, iso8583::PAD_LEFT, 0);
    iso8583::dialect_field(x, 4, iso8583::KIND_LLVAR, iso8583::ENC_BCD, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 10, iso8583::PAD_LEFT, 0);
    var y = iso8583::Message { .. };
    bad += check(iso8583::message_set(y, x, 2, "12A4") == iso8583::ERR_BAD_BYTE, "letter in BCD");
    bad += check(iso8583::message_set(y, x, 3, "12ab") == iso8583::ERR_BAD_BYTE, "lower-case hex");
    bad += check(iso8583::message_set(y, x, 3, "12AB") == iso8583::OK, "upper-case hex");
    bad += check(iso8583::message_set(y, x, 4, "123") == iso8583::ERR_VALUE_LENGTH, "odd digits with a byte count");
    bad += check(iso8583::message_set(y, x, 4, "1234") == iso8583::OK, "even digits with a byte count");
    // Replacing a field many times does not fill the buffer.
    var big = iso8583::Dialect { .. };
    iso8583::dialect_init(big, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    for id in 2..129 {
        if id != 65 { iso8583::dialect_field(big, id, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, 0); }
    }
    var blob: u8[>..] = [];
    for i in 0..999 { blob.push((i % 251) as u8); }
    var z = iso8583::Message { .. };
    var rep_ok = true;
    for i in 0..300 {
        if iso8583::message_set(z, big, 2, blob) != iso8583::OK { rep_ok = false; }
    }
    bad += check(rep_ok, "300 replacements of one field");
    // The data limit counts live bytes and stops at 65535.
    var full = 0;
    var last = iso8583::OK;
    for id in 3..129 {
        if id == 65 { continue; }
        last = iso8583::message_set(z, big, id, blob);
        if last != iso8583::OK { break; }
        full += 1;
    }
    bad += check(last == iso8583::ERR_FULL, "ERR_FULL at the data limit");
    bad += check(iso8583::message_unset(z, 2) == iso8583::OK, "unset frees space");
    bad += check(iso8583::message_set(z, big, 127, blob) == iso8583::OK, "set after unset");
    // message_clear empties everything.
    iso8583::message_clear(z);
    bad += check(!iso8583::message_has(z, 3) && z.mti.len == 0 && z.data.len == 0, "clear");
    return bad;
}

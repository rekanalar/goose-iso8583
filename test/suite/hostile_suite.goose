namespace suite;

import std;
import iso8583 from "../..";
import ref_cases;
import ref_dialects;
import util;

// Unpacks the hex string under the dialect and returns the fault code.
fn fault_of(d: iso8583::Dialect&, hex: const u8[:], m: iso8583::Message&) -> i64 {
    var wire: u8[>..] = [];
    from_hex(wire, hex);
    return iso8583::unpack(m, d, wire);
}

// True when the message holds nothing but the fault field.
fn is_empty(m: iso8583::Message&) -> bool {
    if m.mti.len != 0 || m.data.len != 0 { return false; }
    for id in 0..193 {
        if m.slots[id].present { return false; }
    }
    return true;
}

fn run_faults() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    var m = iso8583::Message { .. };
    // 0200, bitmap with field 2, LLVAR 2 then the value. Hex of ASCII text.
    // "02004000000000000000164111111111111111"
    let good = "3032303034303030303030303030303030303030313634313131313131313131313131313131";
    bad += check(fault_of(d, good, m) == iso8583::OK, "good message");
    // length above the field maximum: "20" for a field with a maximum of 19
    var f = fault_of(d, "303230303430303030303030303030303030303032303431313131313131313131313131313131313131", m);
    bad += check(f == iso8583::ERR_BAD_LENGTH && m.fault_field == 2 && is_empty(m), "length above the maximum");
    // non-digit in the prefix
    f = fault_of(d, "30323030343030303030303030303030303030303A3634313131313131313131313131313131", m);
    bad += check(f == iso8583::ERR_BAD_LENGTH && m.fault_field == 2, "non-digit prefix");
    // truncated value
    f = fault_of(d, "30323030343030303030303030303030303030303136343131313131", m);
    bad += check(f == iso8583::ERR_TRUNCATED && m.fault_field == 2 && is_empty(m), "truncated value");
    // trailing byte
    f = fault_of(d, "30323030343030303030303030303030303030303136343131313131313131313131313131313100", m);
    bad += check(f == iso8583::ERR_TRAILING && is_empty(m), "trailing byte");
    // bit 5 is set, and the custom dialect below has no field 5
    var c = iso8583::Dialect { .. };
    iso8583::dialect_init(c, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    iso8583::dialect_field(c, 3, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 6, iso8583::PAD_LEFT, 0);
    f = fault_of(c, "3032303030383030303030303030303030303030303030303030", m);
    bad += check(f == iso8583::ERR_UNKNOWN_FIELD && m.fault_field == 5, "unknown field");
    // 0x08.. sets bit 5; 0x20.. would set bit 3
    f = fault_of(c, "30323030323030303030303030303030303030303030303030", m);
    bad += check(f == iso8583::ERR_TRUNCATED && m.fault_field == 3, "truncated fixed field");
    // bit 65 in a two-bitmap dialect
    f = fault_of(d, "303230303830303030303030303030303030303038303030303030303030303030303030", m);
    bad += check(f == iso8583::ERR_BAD_BITMAP && m.fault_field == 65 && is_empty(m), "bit 65 with two bitmaps");
    // bad bitmap digits: lower case and a letter outside hex
    f = fault_of(d, "3032303061303030303030303030303030303030", m);
    bad += check(f == iso8583::ERR_BAD_BYTE, "lower-case hex bitmap");
    f = fault_of(d, "3032303047303030303030303030303030303030", m);
    bad += check(f == iso8583::ERR_BAD_BYTE, "letter outside hex in bitmap");
    // bad MTI and short input
    f = fault_of(d, "3032413034303030303030303030303030303030", m);
    bad += check(f == iso8583::ERR_BAD_MTI, "letter in the MTI");
    f = fault_of(d, "303230", m);
    bad += check(f == iso8583::ERR_TRUNCATED, "short MTI");
    f = fault_of(d, "", m);
    bad += check(f == iso8583::ERR_TRUNCATED, "empty input");
    // a BCD nibble above 9 and a pad nibble that is not zero
    var b = iso8583::Dialect { .. };
    iso8583::dialect_init(b, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(b, 2, iso8583::KIND_FIXED, iso8583::ENC_BCD, 0, iso8583::UNIT_NIBBLES, 3, iso8583::PAD_LEFT, 0);
    f = fault_of(b, "3032303040000000000000000123", m);
    bad += check(f == iso8583::OK, "pad nibble zero");
    f = fault_of(b, "3032303040000000000000001123", m);
    bad += check(f == iso8583::ERR_BAD_BYTE && m.fault_field == 2, "pad nibble not zero");
    f = fault_of(b, "30323030400000000000000001A3", m);
    bad += check(f == iso8583::ERR_BAD_BYTE, "nibble above 9 in BCD");
    // input larger than the limit
    var huge: u8[>..] = [];
    for i in 0..(iso8583::MAX_INPUT + 1) { huge.push('0'); }
    bad += check(iso8583::unpack(m, d, huge) == iso8583::ERR_TOO_LONG && is_empty(m), "input above the limit");
    // EBCDIC byte with no ASCII character
    var e = iso8583::Dialect { .. };
    iso8583::dialect_init(e, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(e, 2, iso8583::KIND_FIXED, iso8583::ENC_EBCDIC, 0, iso8583::UNIT_BYTES, 1, iso8583::PAD_LEFT, 0);
    f = fault_of(e, "30323030400000000000000041", m);
    bad += check(f == iso8583::ERR_BAD_BYTE, "EBCDIC byte without an ASCII character");
    return bad;
}

// A cut at each length, a flipped byte at each position, and seeded random
// bytes. Every call must return a code and leave a clean message.
fn run_hostile() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    var m = iso8583::Message { .. };
    var cuts = 0;
    var flips = 0;
    for c in 0..REF_COUNT {
        ref_dialect(d, REF_DIALECT[c]);
        var wire: u8[>..] = [];
        from_hex(wire, REF_WIRE[c]);
        for n in 0..wire.len {
            let f = iso8583::unpack(m, d, wire[0..n]);
            if f == iso8583::OK {
                print("FAIL: cut message ", c, " at ", n, " unpacked\n");
                bad += 1;
            } else if !is_empty(m) {
                print("FAIL: message not empty after a fault\n");
                bad += 1;
            }
            cuts += 1;
        }
        var mutated: u8[>..] = [];
        mutated.append(wire);
        // Several bytes overwritten at once, from a seeded generator.
        var r = rng { (c as u64) + 77 };
        for t in 0..2000 {
            var copy: u8[>..] = [];
            copy.append(wire);
            let k = 1 + r.rand_int(4);
            for q in 0..k { copy[r.rand_int(copy.len)] = r.rand_int(256) as u8; }
            let f = iso8583::unpack(m, d, copy);
            if f == iso8583::OK {
                var again: u8[>..] = [];
                iso8583::pack(again, m, d);
            } else if !is_empty(m) {
                print("FAIL: message not empty after a fault\n");
                bad += 1;
            }
            flips += 1;
        }
        var step: i64 = 1;
        if wire.len > 400 { step = 7; }
        var p = 0;
        while p < wire.len {
            let keep = mutated[p];
            for k in 0..4 {
                mutated[p] = keep ^ (1 << k);
                let f = iso8583::unpack(m, d, mutated);
                if f == iso8583::OK {
                    var again: u8[>..] = [];
                    // A message that still unpacks must pack without a crash.
                    iso8583::pack(again, m, d);
                } else if !is_empty(m) {
                    print("FAIL: message not empty after a fault\n");
                    bad += 1;
                }
                flips += 1;
            }
            mutated[p] = keep;
            p += step;
        }
    }
    bad += check(cuts > 1000 && flips > 1000, "the sweeps ran");
    return bad;
}

fn run_random() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    var m = iso8583::Message { .. };
    var r = rng { 8583 };
    var count = 0;
    for which in 0..4 {
        ref_dialect(d, which);
        for i in 0..100000 {
            let n = r.rand_int(120);
            var buf: u8[>..] = [];
            // Half the inputs start like a message: a plausible MTI and bitmap.
            if i % 2 == 0 {
                buf.append("0200");
            }
            for k in 0..n { buf.push(r.rand_int(256) as u8); }
            let f = iso8583::unpack(m, d, buf);
            if f == iso8583::OK {
                var again: u8[>..] = [];
                iso8583::pack(again, m, d);
            }
            count += 1;
        }
    }
    bad += check(count == 400000, "random inputs ran");
    return bad;
}

// Pack must check each value against the dialect it receives.
fn run_pack_recheck() -> i64 {
    var bad = 0;
    var wide = iso8583::Dialect { .. };
    var narrow = iso8583::Dialect { .. };
    iso8583::dialect_init(wide, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_init(narrow, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(wide, 2, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 99, iso8583::PAD_LEFT, 0);
    iso8583::dialect_field(narrow, 2, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 5, iso8583::PAD_LEFT, 0);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    bad += check(iso8583::message_set(m, wide, 2, "0123456789") == iso8583::OK, "set under the wide dialect");
    var out: u8[>..] = [];
    out.append("junk");
    bad += check(iso8583::pack(out, m, narrow) == iso8583::ERR_VALUE_LENGTH && m.fault_field == 2 && out.len == 0, "pack under the narrow dialect");
    // A field the second dialect does not define.
    var none = iso8583::Dialect { .. };
    iso8583::dialect_init(none, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    bad += check(iso8583::pack(out, m, none) == iso8583::ERR_UNKNOWN_FIELD && m.fault_field == 2, "pack with an undefined field");
    // A missing MTI.
    var e = iso8583::Message { .. };
    bad += check(iso8583::pack(out, e, wide) == iso8583::ERR_BAD_MTI, "pack without MTI");
    // A value set as ASCII does not pack as BCD.
    var bcd = iso8583::Dialect { .. };
    iso8583::dialect_init(bcd, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(bcd, 2, iso8583::KIND_LLVAR, iso8583::ENC_BCD, iso8583::ENC_ASCII, iso8583::UNIT_NIBBLES, 20, iso8583::PAD_LEFT, 0);
    iso8583::message_set(m, wide, 2, "12AB");
    bad += check(iso8583::pack(out, m, bcd) == iso8583::ERR_BAD_BYTE && m.fault_field == 2, "pack letters as BCD");
    return bad;
}

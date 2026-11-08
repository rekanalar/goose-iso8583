namespace suite;

import std;
import iso8583 from "../..";
import ref_cases;
import ref_dialects;
import util;

// Index of the first c in s, or s.len.
fn index_of(s: const u8[:], c: u8) -> i64 {
    for i in 0..s.len {
        if s[i] == c { return i; }
    }
    return s.len;
}

// Checks one id=hex item of a reference case and sets it in built.
fn ref_field(m: iso8583::Message&, built: iso8583::Message&, d: iso8583::Dialect&, item: const u8[:]) -> i64 {
    var bad = 0;
    let eq = index_of(item, '=');
    let id, ok = parse_int(item[0..eq]);
    var want: u8[>..] = [];
    bad += check(from_hex(want, item[eq + 1..item.len]), "reference value is hex");
    var got: u8[>..] = [];
    bad += check(iso8583::message_get(m, id, got) == iso8583::OK, "reference field present");
    bad += eq_bytes(got, want, "reference field value");
    bad += check(iso8583::message_set(built, d, id, want) == iso8583::OK, "reference field set");
    return bad;
}

// Unpacks every reference message, checks the MTI and each field, packs
// the message again, and builds it field by field.
fn run_ref() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    for c in 0..REF_COUNT {
        ref_dialect(d, REF_DIALECT[c]);
        var wire: u8[>..] = [];
        bad += check(from_hex(wire, REF_WIRE[c]), "reference wire is hex");
        var m = iso8583::Message { .. };
        let f = iso8583::unpack(m, d, wire);
        if f != iso8583::OK {
            print("FAIL: unpack of reference case ", c, " gave ", f, " at field ", m.fault_field, "\n");
            bad += 1;
            continue;
        }
        let line = REF_FIELDS[c];
        let semi = index_of(line, ';');
        bad += eq_bytes(m.mti, line[0..semi], "reference mti");
        var built = iso8583::Message { .. };
        bad += check(iso8583::message_set_mti(built, line[0..semi]) == iso8583::OK, "set mti");
        var count = 0;
        var pos = semi + 1;
        while pos < line.len {
            var end = pos;
            while end < line.len && line[end] != ',' { end += 1; }
            bad += ref_field(m, built, d, line[pos..end]);
            count += 1;
            pos = end + 1;
        }
        var n = 0;
        for id in 2..193 { if iso8583::message_has(m, id) { n += 1; } }
        bad += check(n == count, "no extra field after unpack");
        var again: u8[>..] = [];
        bad += check(iso8583::pack(again, m, d) == iso8583::OK, "repack");
        bad += eq_bytes(again, wire, "repack equals the reference bytes");
        var fresh: u8[>..] = [];
        bad += check(iso8583::pack(fresh, built, d) == iso8583::OK, "pack from set calls");
        bad += eq_bytes(fresh, wire, "set and pack equal the reference bytes");
    }
    return bad;
}

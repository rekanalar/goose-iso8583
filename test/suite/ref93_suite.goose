namespace suite;

import std;
import os;
import iso8583 from "../..";
import util;
import ref93_cases;

// Splits the values text at the commas and compares field by field.
fn check_values(msg: iso8583::Message&, text: const u8[:]) -> i64 {
    var bad = 0;
    var got: u8[>..] = [];
    var pos = 0;
    var id = 2;
    let ids: i64[8] = [2, 3, 4, 7, 11, 12, 24, 39];
    var idx = 0;
    while pos <= text.len && idx < 8 {
        var end = pos;
        while end < text.len && text[end] != ',' { end += 1; }
        let want = text[pos..end];
        iso8583::message_get(msg, ids[idx], got);
        bad += eq_bytes(got, want, "ref93 value");
        idx += 1;
        pos = end + 1;
    }
    return bad;
}

fn run_ref93_variant(d: iso8583::Dialect&, sample: const u8[:], wire_hex: const u8[:]) -> i64 {
    var bad = 0;
    var wire: u8[>..] = [];
    if !from_hex(wire, wire_hex) { return check(false, "ref93 hex"); }
    var msg = iso8583::Message { .. };
    bad += check(iso8583::unpack(msg, d, wire) == iso8583::OK, "ref93 unpack");
    bad += check_values(msg, sample);
    var out: u8[>..] = [];
    bad += check(iso8583::pack(out, msg, d) == iso8583::OK, "ref93 pack");
    bad += eq_bytes(out, wire, "ref93 round trip");
    return bad;
}

// The generated table holds no comment beyond the header and no string
// literal at all.
fn scan_table(path: const u8[:], header_lines: i64) -> i64 {
    var bad = 0;
    var src: u8[>..] = [];
    if !read_file(path, src) { return check(false, "table read"); }
    var line = 0;
    var start = 0;
    while start < src.len {
        var end = start;
        while end < src.len && src[end] != '\n' { end += 1; }
        let row = src[start..end];
        if line >= header_lines {
            var k = 0;
            while k < row.len && (row[k] == ' ' || row[k] == 9) { k += 1; }
            if k + 1 < row.len && row[k] == '/' && row[k + 1] == '/' {
                print("FAIL: comment at line ", line, " of ", path, "\n");
                bad += 1;
            }
            if has_run(row, "\"") {
                print("FAIL: string literal at line ", line, " of ", path, "\n");
                bad += 1;
            }
        }
        line += 1;
        start = end + 1;
    }
    return bad;
}

fn run_ref93() -> i64 {
    var bad = 0;
    // The ASCII variant.
    var da = iso8583::Dialect { .. };
    iso8583::dialect_default_1993_ascii(da);
    bad += run_ref93_variant(da, SAMPLE93_FIELDS, SAMPLE93_A);
    // The BCD variant.
    var db = iso8583::Dialect { .. };
    iso8583::dialect_default_1993_binary(db);
    bad += run_ref93_variant(db, SAMPLE93_FIELDS, SAMPLE93_B);
    // The tables hold numbers only.
    bad += scan_table("default_dialect93.goose", 12);
    // Field 39: three digits in 1993, two in 1987.
    var d87 = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d87);
    print("field 39 max_len: 1987 = ", d87.fields[39].max_len, ", 1993 = ", da.fields[39].max_len, "\n");
    bad += check(da.fields[39].max_len == 3, "field 39 is three digits in 1993");
    return bad;
}

namespace suite;

import std;
import iso8583 from "../..";
import util;

fn run_frame() -> i64 {
    var bad = 0;
    var out: u8[>..] = [];
    var want: u8[>..] = [];
    // Hand-built headers.
    bad += check(iso8583::frame_write(out, iso8583::HEADER_ASCII4, "hello") == iso8583::OK, "ascii4 write");
    bad += eq_bytes(out, "0005hello", "ascii4 bytes");
    var body: u8[>..] = [];
    for i in 0..1234 { body.push('x'); }
    bad += check(iso8583::frame_write(out, iso8583::HEADER_BCD2, body) == iso8583::OK, "bcd2 write");
    from_hex(want, "1234");
    bad += eq_bytes(out[0..2], want, "bcd2 bytes");
    bad += check(out.len == 1236, "bcd2 length");
    var b2: u8[>..] = [];
    for i in 0..258 { b2.push('y'); }
    bad += check(iso8583::frame_write(out, iso8583::HEADER_BINARY2, b2) == iso8583::OK, "binary2 write");
    want.clear();
    from_hex(want, "0102");
    bad += eq_bytes(out[0..2], want, "binary2 bytes");
    bad += check(iso8583::frame_write(out, iso8583::HEADER_NONE, "abc") == iso8583::OK && same(out, "abc"), "none write");

    // Round trip for each kind.
    for h in 0..4 {
        bad += check(iso8583::frame_write(out, h, body) == iso8583::OK, "write");
        let n, f = iso8583::frame_read_length(h, out);
        if h == iso8583::HEADER_NONE {
            bad += check(f == iso8583::OK && n == out.len, "none read");
        } else {
            bad += check(f == iso8583::OK && n == body.len, "read length");
        }
    }
    // Faults.
    bad += check(iso8583::frame_write(out, 9, "x") == iso8583::ERR_BAD_ARG, "unknown header kind");
    var long: u8[>..] = [];
    for i in 0..10000 { long.push('z'); }
    bad += check(iso8583::frame_write(out, iso8583::HEADER_ASCII4, long) == iso8583::ERR_TOO_LONG && out.len == 0, "ascii4 body too long");
    bad += check(iso8583::frame_write(out, iso8583::HEADER_BCD2, long) == iso8583::ERR_TOO_LONG, "bcd2 body too long");
    bad += check(iso8583::frame_write(out, iso8583::HEADER_BINARY2, long) == iso8583::OK, "binary2 holds 10000");
    let n1, f1 = iso8583::frame_read_length(iso8583::HEADER_ASCII4, "12");
    bad += check(f1 == iso8583::ERR_TRUNCATED, "short ascii4 header");
    let n2, f2 = iso8583::frame_read_length(iso8583::HEADER_ASCII4, "12x4");
    bad += check(f2 == iso8583::ERR_BAD_LENGTH, "letter in ascii4 header");
    var bad_bcd: u8[>..] = [];
    from_hex(bad_bcd, "12A4");
    let n3, f3 = iso8583::frame_read_length(iso8583::HEADER_BCD2, bad_bcd);
    bad += check(f3 == iso8583::ERR_BAD_LENGTH, "bad bcd2 header");
    var big: u8[>..] = [];
    from_hex(big, "FFFF");
    let n4, f4 = iso8583::frame_read_length(iso8583::HEADER_BINARY2, big);
    bad += check(f4 == iso8583::OK && n4 == 65535, "binary2 FFFF is 65535");
    let n5, f5 = iso8583::frame_read_length(iso8583::HEADER_BINARY2, "x");
    bad += check(f5 == iso8583::ERR_TRUNCATED, "short binary2 header");
    let n6, f6 = iso8583::frame_read_length(7, "xxxx");
    bad += check(f6 == iso8583::ERR_BAD_ARG, "unknown header kind on read");
    var huge: u8[>..] = [];
    for i in 0..(iso8583::MAX_INPUT + 1) { huge.push('0'); }
    let n7, f7 = iso8583::frame_read_length(iso8583::HEADER_NONE, huge);
    bad += check(f7 == iso8583::ERR_TOO_LONG, "no header and too much input");
    return bad;
}

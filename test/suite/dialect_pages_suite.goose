namespace suite;

import std;
import iso8583 from "../..";
import util;
import page_cases;

// One text field of a fixed length.
fn page_dialect(d: iso8583::Dialect&, page: i64) -> i64 {
    var bad = 0;
    bad += check(iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2) == iso8583::OK, "page init");
    bad += check(iso8583::dialect_field(d, 43, iso8583::KIND_FIXED, iso8583::ENC_EBCDIC, 0, iso8583::UNIT_BYTES, 4, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::OK, "page field");
    bad += check(iso8583::dialect_set_page(d, page) == iso8583::OK, "set page");
    return bad;
}

fn run_pages() -> i64 {
    var bad = 0;
    // Every printable ASCII character packs to the table byte of each
    // page, taken from iconv as an independent oracle.
    for p in 0..3 {
        var d = iso8583::Dialect { .. };
        bad += page_dialect(d, p);
        var msg = iso8583::Message { .. };
        iso8583::message_set_mti(msg, "0100");
        var out: u8[>..] = [];
        for start in 0..125 {
            var v: u8[>..] = [];
            for k in 0..4 { v.push((start + k) as u8); }
            if iso8583::message_set(msg, d, 43, v) != iso8583::OK { bad += check(false, "page value"); continue; }
            bad += check(iso8583::pack(out, msg, d) == iso8583::OK, "page pack");
            for k in 0..4 {
                bad += check(out[20 + k] == PAGE_CASES[p * 128 + start + k], "page byte");
            }
        }
    }
    // A dialect on page 037 and 1047 round trips MTI, bitmap, prefix and data.
    for p in 1..3 {
        var d = iso8583::Dialect { .. };
        bad += check(iso8583::dialect_init(d, iso8583::ENC_EBCDIC, iso8583::BITMAP_HEX_EBCDIC, 2) == iso8583::OK, "ebcdic init");
        bad += check(iso8583::dialect_field(d, 2, iso8583::KIND_LLVAR, iso8583::ENC_EBCDIC, iso8583::ENC_EBCDIC, iso8583::UNIT_BYTES, 19, iso8583::PAD_LEFT, iso8583::MASK_PAN) == iso8583::OK, "ebcdic pan");
        bad += check(iso8583::dialect_set_page(d, p) == iso8583::OK, "ebcdic page");
        var msg = iso8583::Message { .. };
        iso8583::message_set_mti(msg, "0100");
        bad += check(iso8583::message_set(msg, d, 2, "4111111111111111") == iso8583::OK, "ebcdic set");
        var wire: u8[>..] = [];
        bad += check(iso8583::pack(wire, msg, d) == iso8583::OK, "ebcdic pack");
        var back = iso8583::Message { .. };
        bad += check(iso8583::unpack(back, d, wire) == iso8583::OK, "ebcdic unpack");
        var got: u8[>..] = [];
        iso8583::message_get(back, 2, got);
        bad += eq_bytes(got, "4111111111111111", "ebcdic round trip");
    }
    // A bad page is a bad argument.
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    bad += check(iso8583::dialect_set_page(d, 3) == iso8583::ERR_BAD_ARG, "bad page");
    bad += check(iso8583::dialect_set_page(d, -1) == iso8583::ERR_BAD_ARG, "negative page");
    return bad;
}

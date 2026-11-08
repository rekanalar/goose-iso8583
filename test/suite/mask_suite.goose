namespace suite;

import std;
import iso8583 from "../..";
import util;

fn count_lines(t: const u8[:]) -> i64 {
    var n = 0;
    for i in 0..t.len { if t[i] == '\n' { n += 1; } }
    return n;
}

fn run_mask() -> i64 {
    var bad = 0;
    var out: u8[>..] = [];
    iso8583::mask_pan(out, "4111111111111111");
    bad += eq_bytes(out, "411111******1111", "mask 16");
    out.clear();
    iso8583::mask_pan(out, "378282246310005");
    bad += eq_bytes(out, "37828******0005", "mask 15");
    out.clear();
    iso8583::mask_pan(out, "6200000000000005123");
    bad += eq_bytes(out, "620000*********5123", "mask 19");
    out.clear();
    iso8583::mask_pan(out, "12345678");
    bad += eq_bytes(out, "******78", "mask 8");
    out.clear();
    iso8583::mask_pan(out, "1234567");
    bad += eq_bytes(out, "******7", "mask 7");
    out.clear();
    iso8583::mask_pan(out, "123456");
    bad += eq_bytes(out, "******", "mask 6");
    out.clear();
    iso8583::mask_pan(out, "12");
    bad += eq_bytes(out, "**", "mask 2");
    out.clear();
    iso8583::mask_pan(out, "");
    bad += eq_bytes(out, "", "mask empty");
    out.clear();
    iso8583::mask_pan(out, "41111111A1111111");
    bad += eq_bytes(out, "411111******1111", "a letter in the shown part is hidden or absent");

    // For every PAN length the text form hides at least six digits (when the
    // PAN has more than six) and never holds a window of eleven PAN digits.
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    let pan = "4929123456789012345";
    for n in 7..20 {
        let digits = pan[0..n];
        var m = iso8583::Message { .. };
        iso8583::message_set_mti(m, "0100");
        iso8583::message_set(m, d, 2, digits);
        var text: u8[>..] = [];
        bad += check(iso8583::message_text(text, m, d) == iso8583::OK, "text form");
        var shown = 0;
        for i in 0..text.len { if text[i] >= '0' && text[i] <= '9' { shown += 1; } }
        // The MTI "0100" and the field id "002" and the length add digits.
        var len_digits = 1;
        if n >= 10 { len_digits = 2; }
        let extra = 4 + 3 + len_digits;
        if shown - extra > 10 { print("FAIL: PAN of ", n, " digits shows ", shown - extra, "\n"); bad += 1; }
        if n >= 11 {
            for w in 0..(n - 10) {
                if has_run(text, digits[w..w + 11]) { print("FAIL: window of 11 digits in text, PAN ", n, "\n"); bad += 1; }
            }
        }
        if has_run(text, digits) { print("FAIL: whole PAN in text\n"); bad += 1; }
    }

    // Fields with the full mask show only '*'.
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    iso8583::message_set(m, d, 2, "4111111111111111");
    iso8583::message_set(m, d, 35, "4111111111111111=2512101");
    iso8583::message_set(m, d, 52, "ABCDEF0123456789");
    iso8583::message_set(m, d, 55, "9F2608AABBCCDDEEFF0011");
    iso8583::message_set(m, d, 41, "TERM0001");
    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);
    bad += check(has_run(text, "F041 [8] TERM0001\n"), "unmasked field shows");
    bad += check(has_run(text, "F035 [24] ************************\n"), "track 2 fully masked");
    bad += check(has_run(text, "F052 [16] ****************\n"), "PIN data fully masked");
    bad += check(!has_run(text, "9F26") && !has_run(text, "2512101"), "EMV and expiry hidden");
    bad += check(has_run(text, "MTI 0200\n"), "MTI line");

    // A value cannot forge a log line.
    var nl: u8[>..] = [];
    from_hex(nl, "41420A46303032205B5D");
    var m2 = iso8583::Message { .. };
    iso8583::message_set_mti(m2, "0200");
    iso8583::message_set(m2, d, 48, nl);
    iso8583::message_text(text, m2, d);
    bad += check(count_lines(text) == 2, "control bytes do not add lines");
    bad += check(has_run(text, "AB.F002 []\n"), "control byte shown as a dot");

    // A custom field can carry any mask mode.
    var c = iso8583::Dialect { .. };
    iso8583::dialect_init(c, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::dialect_field(c, 2, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 30, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    iso8583::dialect_field(c, 3, iso8583::KIND_FIXED, iso8583::ENC_BINARY, 0, iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    iso8583::dialect_field(c, 4, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 30, iso8583::PAD_LEFT, iso8583::MASK_PAN);
    var m3 = iso8583::Message { .. };
    iso8583::message_set_mti(m3, "0200");
    iso8583::message_set(m3, c, 2, "SECRET");
    var bin: u8[>..] = [];
    from_hex(bin, "BEEF");
    iso8583::message_set(m3, c, 3, bin);
    iso8583::message_set(m3, c, 4, "5500000000000004");
    iso8583::message_text(text, m3, c);
    bad += check(has_run(text, "F002 [6] ******\n") && !has_run(text, "SECRET"), "custom full mask");
    bad += check(has_run(text, "F003 [2] BEEF\n"), "binary shown as hex");
    bad += check(has_run(text, "F004 [16] 550000******0004\n"), "custom PAN mask");
    // A field that the dialect does not know is masked in full.
    var none = iso8583::Dialect { .. };
    iso8583::dialect_init(none, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2);
    iso8583::message_text(text, m3, none);
    bad += check(!has_run(text, "SECRET") && !has_run(text, "5500000000000004") && !has_run(text, "550000"), "unknown field masked in full");
    return bad;
}

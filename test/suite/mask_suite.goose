namespace suite;

import std;
import iso8583 from "../..";
import util;

fn count_lines(t: const u8[:]) -> i64 {
    var n = 0;
    for i in 0..t.len { if t[i] == '\n' { n += 1; } }
    return n;
}

// The safe defaults: fields 48 and 120 to 127 show no value bytes.
fn run_mask_defaults() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    for id in 48..49 {
        bad += check(iso8583::message_set(m, d, id, "4111111111111111SECRET") == iso8583::OK, "set private");
    }
    for id in 120..128 {
        bad += check(iso8583::message_set(m, d, id, "4111111111111111SECRET") == iso8583::OK, "set national");
    }
    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);
    bad += check(!has_run(text, "4111111111111111"), "no pan in the private fields");
    bad += check(!has_run(text, "SECRET"), "no secret in the text");
    var runs = 0;
    for i in 0..text.len {
        if text[i] == '*' { runs += 1; }
    }
    bad += check(runs >= 9 * 21, "all private bytes masked");
    return bad;
}

// MASK_INHERIT on subfields takes the mode of the nearest container.
fn run_mask_inherit() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_BER, 0);
    // A PAN subfield under a MASK_NONE container: the subfield mode wins.
    iso8583::dialect_sub(d, iso8583::path1(55), 0x9F26, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 19, iso8583::PAD_LEFT, iso8583::MASK_PAN);
    // An inherit subfield under the MASK_NONE container: shows the value.
    iso8583::dialect_sub(d, iso8583::path1(55), 0x95, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    // A nested container with MASK_FULL, holding an inherit subfield.
    iso8583::dialect_sub(d, iso8583::path1(55), 0xA1, iso8583::KIND_LLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 99, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    iso8583::dialect_composite(d, iso8583::path2(55, 0xA1), iso8583::COMPOSITE_BER, 0);
    iso8583::dialect_sub(d, iso8583::path2(55, 0xA1), 0x5A, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 19, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0100");
    var payload: u8[>..] = [];
    // 9F26 10 4111111111111111, 95 02 OK, A1 len 1D: 5A 0E 4111111111111111
    payload.push(0x9F);
    payload.push(0x26);
    payload.push(0x10);
    payload.append("4111111111111111");
    payload.push(0x95);
    payload.push(0x02);
    payload.append("OK");
    var inner: u8[>..] = [];
    inner.push(0x5A);
    inner.push(0x10);
    inner.append("4111111111111111");
    payload.push(0xA1);
    payload.push(inner.len as u8);
    payload.append(inner);
    bad += check(iso8583::message_set(m, d, 55, payload) == iso8583::OK, "set inherit payload");
    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);
    // The PAN subfield shows the first-six last-four form.
    bad += check(has_run(text, "411111******1111"), "pan subfield shows the masked form");
    // The inherit subfield under MASK_NONE shows the value.
    bad += check(has_run(text, "F055.95 [2] OK"), "inherit shows the value under mask none");
    // The inherit subfield under the MASK_FULL container shows stars.
    bad += check(has_run(text, "F055.A1.5A [16] ****************"), "inherit takes the nearest container mode");
    bad += check(!has_run(text, "4111111111111111"), "no full pan anywhere");
    return bad;
}

fn run_mask() -> i64 {
    var bad = 0;
    bad += run_mask_defaults();
    bad += run_mask_inherit();
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
    iso8583::message_set(m2, d, 62, nl);
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

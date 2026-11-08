namespace suite;

import std;
import iso8583 from "../..";
import util;
import tlv_cases;

// The value of one hex digit, or -1.
fn hexv(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// Reads a hex tag such as 9F26 as a number.
fn tag_of(h: const u8[:]) -> i64 {
    var v: i64 = 0;
    for i in 0..h.len { v = v * 16 + hexv(h[i]); }
    return v;
}

// Splits one TAG:VALUE pair of the entries text at pos. Returns the
// tag, the value bytes appended to val, and the position after the pair.
fn next_entry(text: const u8[:], pos: i64, val: u8[>..]&) -> i64, i64 {
    var i = pos;
    while i < text.len && text[i] != ':' { i += 1; }
    let tag = tag_of(text[pos..i]);
    i += 1;
    var j = i;
    while j < text.len && text[j] != ',' { j += 1; }
    val.clear();
    from_hex(val, text[i..j]);
    return tag, j + 1;
}

// Defines field 55 as a BER container with the tags of the entries text.
fn ber_dialect(d: iso8583::Dialect&, text: const u8[:]) -> i64 {
    var bad = 0;
    bad += check(iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2) == iso8583::OK, "init");
    bad += check(iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                        iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL) == iso8583::OK, "field 55");
    bad += check(iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_BER, 0) == iso8583::OK, "composite 55");
    var pos = 0;
    var val: u8[>..] = [];
    while pos < text.len {
        let tag, np = next_entry(text, pos, val);
        pos = np;
        let f = iso8583::dialect_sub(d, iso8583::path1(55), tag, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY,
                                     iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
        bad += check(f == iso8583::OK, "sub");
    }
    return bad;
}

// Builds the wire form of a message that holds only field 55 with the
// payload given in hex. The bitmap is hand-built.
fn wire55(out: u8[>..]&, payload_hex: const u8[:]) {
    out.clear();
    out.append("0100");
    out.append("0000000000000200");
    var payload: u8[>..] = [];
    from_hex(payload, payload_hex);
    format_int(out, payload.len, 10, 3, '0');
    out.append(payload);
}

// Unpacks a hand-built wire and expects the fault on field 55.
fn expect_fault(d: iso8583::Dialect&, payload_hex: const u8[:], want: i64, what: const u8[:]) -> i64 {
    var wire: u8[>..] = [];
    wire55(wire, payload_hex);
    var msg = iso8583::Message { .. };
    let f = iso8583::unpack(msg, d, wire);
    var bad = check(f == want, what);
    bad += check(msg.fault_field == 55, what);
    bad += check(!iso8583::message_has(msg, 55) && msg.mti.len == 0, what);
    return bad;
}

fn run_samples() -> i64 {
    var bad = 0;
    for c in 0..tlv_count() {
        let entries = tlv_entries(c);
        var d = iso8583::Dialect { .. };
        bad += ber_dialect(d, entries);
        var payload: u8[>..] = [];
        from_hex(payload, tlv_payload(c));
        var msg = iso8583::Message { .. };
        bad += check(iso8583::message_set_mti(msg, "0100") == iso8583::OK, "mti");
        bad += check(iso8583::message_set(msg, d, 55, payload) == iso8583::OK, "set container");
        // Each entry reads back by tag.
        var pos = 0;
        var val: u8[>..] = [];
        var got: u8[>..] = [];
        while pos < entries.len {
            let tag, np = next_entry(entries, pos, val);
            pos = np;
            bad += check(iso8583::message_has_sub(msg, d, iso8583::path2(55, tag)), "has sub");
            bad += check(iso8583::message_get_sub(msg, d, iso8583::path2(55, tag), got) == iso8583::OK, "get sub");
            bad += eq_bytes(got, val, "sub value");
        }
        // Pack and unpack give the same bytes.
        var wire: u8[>..] = [];
        bad += check(iso8583::pack(wire, msg, d) == iso8583::OK, "pack");
        var back = iso8583::Message { .. };
        bad += check(iso8583::unpack(back, d, wire) == iso8583::OK, "unpack");
        var wire2: u8[>..] = [];
        bad += check(iso8583::pack(wire2, back, d) == iso8583::OK, "repack");
        bad += eq_bytes(wire2, wire, "round trip bytes");
        bad += check(iso8583::message_get(back, 55, got) == iso8583::OK, "get container");
        bad += eq_bytes(got, payload, "container bytes");
    }
    return bad;
}

fn run_paths() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    bad += ber_dialect(d, "9F26:00,95:00,5F2A:00,9F10:00");
    var msg = iso8583::Message { .. };
    var got: u8[>..] = [];
    var want: u8[>..] = [];
    // A subfield on an absent container makes the container.
    from_hex(want, "1122334455667788");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0x9F26), want) == iso8583::OK, "set first");
    bad += check(iso8583::message_has(msg, 55), "container made");
    want.clear();
    from_hex(want, "0000000000");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0x95), want) == iso8583::OK, "set second");
    // The wire order holds: the new tag goes last.
    bad += check(iso8583::message_get(msg, 55, got) == iso8583::OK, "get container");
    var hex: u8[>..] = [];
    to_hex(hex, got);
    bad += eq_bytes(hex, "9F2608112233445566778895050000000000" , "order after two sets");
    // A replace keeps the place.
    want.clear();
    from_hex(want, "AABBCCDDEEFF0011");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0x9F26), want) == iso8583::OK, "replace");
    iso8583::message_get(msg, 55, got);
    to_hex(hex, got);
    bad += eq_bytes(hex, "9F2608AABBCCDDEEFF001195050000000000", "order after replace");
    // A replace with another length.
    want.clear();
    from_hex(want, "AABB");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0x9F26), want) == iso8583::OK, "replace shorter");
    iso8583::message_get(msg, 55, got);
    to_hex(hex, got);
    bad += eq_bytes(hex, "9F2602AABB95050000000000", "shorter replace");
    // Unset.
    bad += check(iso8583::message_unset_sub(msg, d, iso8583::path2(55, 0x9F26)) == iso8583::OK, "unset");
    bad += check(!iso8583::message_has_sub(msg, d, iso8583::path2(55, 0x9F26)), "gone");
    bad += check(iso8583::message_has_sub(msg, d, iso8583::path2(55, 0x95)), "other stays");
    bad += check(iso8583::message_unset_sub(msg, d, iso8583::path2(55, 0x9F26)) == iso8583::ERR_NOT_SET, "unset twice");
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path2(55, 0x9F26), got) == iso8583::ERR_NOT_SET, "get absent");
    // A subfield that breaks its spec changes nothing.
    var before: u8[>..] = [];
    iso8583::message_get(msg, 55, before);
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0x1234), "x") == iso8583::ERR_BAD_TAG, "undefined tag");
    iso8583::message_get(msg, 55, got);
    bad += eq_bytes(got, before, "unchanged after fault");
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path1(55), got) == iso8583::ERR_BAD_ARG, "path too short");
    // The text form shows one line per subfield, with the value masked.
    var text: u8[>..] = [];
    iso8583::message_text(text, msg, d);
    bad += check(has_run(text, "F055.95 [5] *****"), "subfield line");
    bad += check(!has_run(text, "F055.9F26"), "no line for a removed tag");
    bad += check(!has_run(text, "AABB"), "no value bytes in the text");
    return bad;
}

// A nested container: field 55 holds tag A1, which holds tag B1, which
// holds tag C1.
fn nested_dialect(d: iso8583::Dialect&) -> i64 {
    var bad = 0;
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    bad += check(iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                        iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL) == iso8583::OK, "n field");
    bad += check(iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_BER, 0) == iso8583::OK, "n c1");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(55), 0xA1, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                      iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_INHERIT) == iso8583::OK, "n a1");
    bad += check(iso8583::dialect_composite(d, iso8583::path2(55, 0xA1), iso8583::COMPOSITE_BER, 0) == iso8583::OK, "n c2");
    bad += check(iso8583::dialect_sub(d, iso8583::path2(55, 0xA1), 0xB1, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                      iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_INHERIT) == iso8583::OK, "n b1");
    bad += check(iso8583::dialect_composite(d, iso8583::path3(55, 0xA1, 0xB1), iso8583::COMPOSITE_BER, 0) == iso8583::OK, "n c3");
    bad += check(iso8583::dialect_sub(d, iso8583::path3(55, 0xA1, 0xB1), 0xC1, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                      iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_INHERIT) == iso8583::OK, "n c1 leaf");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(55), 0x95, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                      iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_INHERIT) == iso8583::OK, "n 95");
    return bad;
}

fn run_nested() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    bad += nested_dialect(d);
    var msg = iso8583::Message { .. };
    var got: u8[>..] = [];
    var v: u8[>..] = [];
    // An intermediate container must exist.
    from_hex(v, "AA");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path4(55, 0xA1, 0xB1, 0xC1), v) == iso8583::ERR_NOT_SET, "deep set without parents");
    // Build the levels from the top: the empty containers first.
    var empty: u8[>..] = [];
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0x95), v) == iso8583::OK, "top leaf");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(55, 0xA1), empty) == iso8583::OK, "empty level 2");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path3(55, 0xA1, 0xB1), empty) == iso8583::OK, "empty level 3");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path4(55, 0xA1, 0xB1, 0xC1), v) == iso8583::OK, "deep leaf");
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path4(55, 0xA1, 0xB1, 0xC1), got) == iso8583::OK, "deep get");
    bad += eq_bytes(got, v, "deep value");
    var hex: u8[>..] = [];
    iso8583::message_get(msg, 55, got);
    to_hex(hex, got);
    bad += eq_bytes(hex, "9501AAA105B103C101AA", "nested bytes");
    return bad;
}

// One fault case per code, for unpack and for message_set.
fn run_composite_faults() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    bad += ber_dialect(d, "9F26:00,95:00,5F2A:00");
    bad += expect_fault(d, "9501AA9501BB", iso8583::ERR_DUPLICATE, "duplicate tag");
    bad += expect_fault(d, "9A03241002", iso8583::ERR_BAD_TAG, "undefined tag");
    bad += expect_fault(d, "950600000000", iso8583::ERR_TRUNCATED, "length past the end");
    bad += expect_fault(d, "9F26", iso8583::ERR_TRUNCATED, "tag without length");
    bad += expect_fault(d, "9F2610", iso8583::ERR_TRUNCATED, "length without value");
    bad += expect_fault(d, "9501AA5F", iso8583::ERR_TRUNCATED, "cut second tag byte");
    bad += expect_fault(d, "9F", iso8583::ERR_TRUNCATED, "cut tag");
    bad += expect_fault(d, "9581050000000000", iso8583::ERR_BAD_LENGTH, "non-minimal length");
    bad += expect_fault(d, "9580", iso8583::ERR_BAD_LENGTH, "indefinite length");
    bad += expect_fault(d, "958300000500000000", iso8583::ERR_BAD_LENGTH, "three byte length");
    bad += expect_fault(d, "958200050000000000", iso8583::ERR_BAD_LENGTH, "non-minimal long length");
    bad += expect_fault(d, "9FA8A813", iso8583::ERR_BAD_TAG, "tag of four bytes");
    // The same payloads are refused by message_set and leave the message alone.
    var msg = iso8583::Message { .. };
    var payload: u8[>..] = [];
    from_hex(payload, "9501AA9501BB");
    bad += check(iso8583::message_set(msg, d, 55, payload) == iso8583::ERR_DUPLICATE, "set duplicate");
    bad += check(!iso8583::message_has(msg, 55), "nothing set");
    // A subfield value that breaks its spec changes nothing.
    var d2 = iso8583::Dialect { .. };
    iso8583::dialect_init(d2, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    iso8583::dialect_field(d2, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    iso8583::dialect_composite(d2, iso8583::path1(55), iso8583::COMPOSITE_BER, 0);
    iso8583::dialect_sub(d2, iso8583::path1(55), 0x5F2A, iso8583::KIND_FIXED, iso8583::ENC_BINARY, 0, iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    var two: u8[>..] = [];
    from_hex(two, "0840");
    bad += check(iso8583::message_set_sub(msg, d2, iso8583::path2(55, 0x5F2A), two) == iso8583::OK, "set fixed");
    var one: u8[>..] = [];
    from_hex(one, "08");
    bad += check(iso8583::message_set_sub(msg, d2, iso8583::path2(55, 0x5F2A), one) == iso8583::ERR_VALUE_LENGTH, "short fixed value");
    var got: u8[>..] = [];
    bad += check(iso8583::message_get_sub(msg, d2, iso8583::path2(55, 0x5F2A), got) == iso8583::OK, "still there");
    bad += eq_bytes(got, two, "value unchanged");
    // A BER length that does not match a fixed subfield.
    bad += expect_fault(d2, "5F2A03084000", iso8583::ERR_BAD_LENGTH, "fixed length mismatch");
    return bad;
}

// The limits of the dialect calls.
fn run_composite_limits() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    bad += nested_dialect(d);
    // Level 3 is the last container.
    bad += check(iso8583::dialect_composite(d, iso8583::path4(55, 0xA1, 0xB1, 0xC1), iso8583::COMPOSITE_BER, 0) == iso8583::ERR_DEPTH, "container at level 4");
    // A container must exist before it takes subfields.
    bad += check(iso8583::dialect_sub(d, iso8583::path1(56), 1, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 9, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_UNKNOWN_FIELD, "sub of an undefined field");
    bad += check(iso8583::dialect_sub(d, iso8583::path2(55, 0x95), 1, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 9, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_BAD_ARG, "sub of a leaf");
    // A duplicate tag, a bad BER tag, a bad mode.
    bad += check(iso8583::dialect_sub(d, iso8583::path1(55), 0x95, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 9, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_DUPLICATE, "duplicate tag in dialect");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(55), 0x1F, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 9, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_BAD_TAG, "tag 1F alone is not a tag");
    bad += check(iso8583::dialect_composite(d, iso8583::path1(55), 9, 0) == iso8583::ERR_BAD_ARG, "bad mode");
    // MASK_INHERIT is for subfields only.
    bad += check(iso8583::dialect_field(d, 56, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 4, iso8583::PAD_LEFT, iso8583::MASK_INHERIT) == iso8583::ERR_BAD_ARG, "inherit on a field");
    bad += check(!iso8583::dialect_has(d, 56), "field 56 stays undefined");
    // A BER container needs a binary field.
    bad += check(iso8583::dialect_field(d, 57, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 99, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::OK, "text field");
    bad += check(iso8583::dialect_composite(d, iso8583::path1(57), iso8583::COMPOSITE_BER, 0) == iso8583::ERR_BAD_ARG, "BER needs binary");
    // 64 subfields per container, 192 in all.
    var d2 = iso8583::Dialect { .. };
    iso8583::dialect_init(d2, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    for fid in 48..52 {
        iso8583::dialect_field(d2, fid, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL);
        bad += check(iso8583::dialect_composite(d2, iso8583::path1(fid), iso8583::COMPOSITE_TAGGED, 3) == iso8583::OK, "tagged container");
    }
    for fid in 48..51 {
        for t in 0..64 {
            let r = iso8583::dialect_sub(d2, iso8583::path1(fid), t, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 1, iso8583::PAD_LEFT, iso8583::MASK_NONE);
            bad += check(r == iso8583::OK, "fill subs");
        }
    }
    bad += check(iso8583::dialect_sub(d2, iso8583::path1(48), 64, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 1, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_BAD_ARG, "65th sub of a container");
    bad += check(iso8583::dialect_sub(d2, iso8583::path1(51), 0, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 1, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_BAD_ARG, "193rd sub in all");
    return bad;
}

// A tagged container and a list, with BCD and EBCDIC subfields.
fn run_tagged_list() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    // Field 48: tagged, tag width 2.
    iso8583::dialect_field(d, 48, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 99, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    bad += check(iso8583::dialect_composite(d, iso8583::path1(48), iso8583::COMPOSITE_TAGGED, 2) == iso8583::OK, "48 tagged");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(48), 1, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 3, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::OK, "tag 1");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(48), 7, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 20, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::OK, "tag 7");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(48), 100, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 3, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::ERR_BAD_TAG, "tag wider than the width");
    var msg = iso8583::Message { .. };
    iso8583::message_set_mti(msg, "0200");
    bad += check(iso8583::message_set(msg, d, 48, "01ABC0705hello") == iso8583::OK, "set tagged");
    var got: u8[>..] = [];
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path2(48, 7), got) == iso8583::OK, "get tag 7");
    bad += eq_bytes(got, "hello", "tag 7 value");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(48, 1), "XYZ") == iso8583::OK, "set tag 1");
    iso8583::message_get(msg, 48, got);
    bad += eq_bytes(got, "01XYZ0705hello", "tagged order");
    bad += check(iso8583::message_unset_sub(msg, d, iso8583::path2(48, 1)) == iso8583::OK, "unset tag 1");
    iso8583::message_get(msg, 48, got);
    bad += eq_bytes(got, "0705hello", "tagged after unset");
    bad += check(iso8583::message_set(msg, d, 48, "01ABC01ABC") == iso8583::ERR_DUPLICATE, "tagged duplicate");
    bad += check(iso8583::message_set(msg, d, 48, "0xABC") == iso8583::ERR_BAD_TAG, "tag with a letter");
    bad += check(iso8583::message_set(msg, d, 48, "03ABC") == iso8583::ERR_BAD_TAG, "undefined tag");
    bad += check(iso8583::message_set(msg, d, 48, "0705hel") == iso8583::ERR_TRUNCATED, "cut value");
    // Field 120: a list of ASCII, LLVAR and BCD subfields.
    iso8583::dialect_field(d, 120, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 99, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    bad += check(iso8583::dialect_composite(d, iso8583::path1(120), iso8583::COMPOSITE_LIST, 0) == iso8583::OK, "120 list");
    iso8583::dialect_sub(d, iso8583::path1(120), 0, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 3, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    iso8583::dialect_sub(d, iso8583::path1(120), 0, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 9, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    bad += check(iso8583::dialect_sub(d, iso8583::path1(120), 0, iso8583::KIND_FIXED, iso8583::ENC_BCD, 0, iso8583::UNIT_NIBBLES, 5, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::OK, "bcd sub");
    bad += check(iso8583::dialect_sub(d, iso8583::path1(120), 0, iso8583::KIND_FIXED, iso8583::ENC_EBCDIC, 0, iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_NONE) == iso8583::OK, "ebcdic sub");
    var payload: u8[>..] = [];
    // ABC, 03xyz, 5 BCD digits (3 bytes, pad nibble left), EBCDIC "Ab".
    payload.append("ABC03xyz");
    from_hex(payload, "012345C182");
    bad += check(iso8583::message_set(msg, d, 120, payload) == iso8583::OK, "set list");
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path2(120, 3), got) == iso8583::OK, "get bcd");
    bad += eq_bytes(got, "12345", "bcd logical value");
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path2(120, 4), got) == iso8583::OK, "get ebcdic");
    bad += eq_bytes(got, "Ab", "ebcdic logical value");
    bad += check(iso8583::message_get_sub(msg, d, iso8583::path2(120, 2), got) == iso8583::OK, "get llvar");
    bad += eq_bytes(got, "xyz", "llvar value");
    // Replace the BCD value: the odd digit count is padded again.
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(120, 3), "98765") == iso8583::OK, "set bcd");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(120, 4), "Zq") == iso8583::OK, "set ebcdic");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(120, 2), "longer") == iso8583::OK, "set llvar");
    iso8583::message_get(msg, 120, got);
    var hex: u8[>..] = [];
    to_hex(hex, got);
    // ABC 06longer 098765 E998
    bad += eq_bytes(hex, "41424330366C6F6E676572098765E998", "list after sets");
    bad += check(iso8583::message_set_sub(msg, d, iso8583::path2(120, 3), "12a45") == iso8583::ERR_BAD_BYTE, "letter in bcd");
    bad += check(iso8583::message_unset_sub(msg, d, iso8583::path2(120, 3)) == iso8583::ERR_BAD_ARG, "list subfield stays");
    // A list needs all its subfields.
    bad += check(iso8583::message_set(msg, d, 120, "ABC03xyz") == iso8583::ERR_TRUNCATED, "list shortfall");
    var msg2 = iso8583::Message { .. };
    bad += check(iso8583::message_set_sub(msg2, d, iso8583::path2(120, 1), "ABC") == iso8583::ERR_NOT_SET, "list cannot start empty");
    // Pack and unpack the whole message.
    var wire: u8[>..] = [];
    bad += check(iso8583::pack(wire, msg, d) == iso8583::OK, "pack list message");
    var back = iso8583::Message { .. };
    bad += check(iso8583::unpack(back, d, wire) == iso8583::OK, "unpack list message");
    var wire2: u8[>..] = [];
    iso8583::pack(wire2, back, d);
    bad += eq_bytes(wire2, wire, "list round trip");
    return bad;
}

fn run_composite() -> i64 {
    var bad = 0;
    bad += run_samples();
    bad += run_paths();
    bad += run_nested();
    bad += run_composite_faults();
    bad += run_composite_limits();
    bad += run_tagged_list();
    return bad;
}

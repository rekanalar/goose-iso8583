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

// The cost of one set does not depend on the count of the set fields.
// A set replaces in place or appends; other slots keep their offsets
// unless a compaction happens, and the live count stays exact.
fn run_message_cost() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    // Set 191 fields.
    for id in 2..193 {
        if id == 65 || !d.fields[id].defined { continue; }
        let spec = d.fields[id];
        var v: u8[>..] = [];
        let n = spec.max_len;
        if spec.kind == iso8583::KIND_FIXED {
            for i in 0..n { v.push('x'); }
            if iso8583::message_set(m, d, id, v) != iso8583::OK { bad += check(false, "cost set fixed"); }
        } else {
            for i in 0..(if n < 5 { n } else { 5 }) { v.push('y'); }
            if iso8583::message_set(m, d, id, v) != iso8583::OK { bad += check(false, "cost set var"); }
        }
    }
    bad += check(m.live == m.data.len, "live equals the buffer after 191 sets");
    // Offsets of every slot before the changes.
    var offs: i64[193] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    var lens: i64[193] = offs;
    for id in 2..193 {
        offs[id] = m.slots[id].off;
        lens[id] = m.slots[id].len;
    }
    var compacted = false;
    // Replace field 20 with a value of the same length: offsets hold.
    let rid = 44;
    var v44: u8[>..] = [];
    for i in 0..lens[rid] { v44.push('z'); }
    bad += check(iso8583::message_set(m, d, rid, v44) == iso8583::OK, "replace same length");
    for id in 2..193 {
        if id == 65 || !m.slots[id].present { continue; }
        bad += check(m.slots[id].off == offs[id], "offset holds after same length");
    }
    // Replace field 44 with a shorter value: offsets hold.
    v44.clear();
    for i in 0..(lens[rid] - 1) { v44.push('w'); }
    bad += check(iso8583::message_set(m, d, rid, v44) == iso8583::OK, "replace shorter");
    bad += check(m.slots[rid].off == offs[rid], "shorter replace keeps the offset");
    for id in 2..193 {
        if id == 65 || !m.slots[id].present || id == rid { continue; }
        bad += check(m.slots[id].off == offs[id], "offset holds after shorter");
    }
    // Replace field 44 with a longer value: the value moves to the end,
    // the other offsets hold, and a hole appears.
    v44.clear();
    for i in 0..(lens[rid] + 1) { v44.push('v'); }
    bad += check(iso8583::message_set(m, d, rid, v44) == iso8583::OK, "replace longer");
    for id in 2..193 {
        if id == 65 || !m.slots[id].present || id == rid { continue; }
        bad += check(m.slots[id].off == offs[id], "offset holds after longer");
    }
    let live_before = m.live;
    bad += check(m.live == sum_lens(m), "live equals the sum of the lengths");
    // Unset field 30: a hole of zeros, the other offsets hold. Field 44
    // moved to the end at its longer replace, so compare the others
    // with the offsets of now.
    var now_offs: i64[193] = offs;
    for id in 2..193 {
        if id == 65 || !m.slots[id].present { continue; }
        now_offs[id] = m.slots[id].off;
    }
    bad += check(iso8583::message_unset(m, 30) == iso8583::OK, "unset 30");
    for id in 2..193 {
        if id == 65 || !m.slots[id].present || id == 30 { continue; }
        bad += check(m.slots[id].off == now_offs[id], "offset holds after unset");
    }
    bad += check(m.live == live_before - lens[30], "live drops by the unset length");
    // Every value still reads back right.
    var got: u8[>..] = [];
    var read_ok = true;
    for id in 2..193 {
        if id == 65 || !m.slots[id].present { continue; }
        iso8583::message_get(m, id, got);
        if got.len != m.slots[id].len { read_ok = false; }
    }
    bad += check(read_ok, "values read back after the changes");
    // A trailing hole is cut at once.
    var big = iso8583::Dialect { .. };
    iso8583::dialect_init(big, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    for fid in 48..116 {
        iso8583::dialect_field(big, fid, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    }
    var z = iso8583::Message { .. };
    var blob: u8[>..] = [];
    for i in 0..999 { blob.push('b'); }
    // 65 fields of 999 bytes fill the buffer to 64935.
    var set_count = 0;
    for fid in 48..116 {
        if iso8583::message_set(z, big, fid, blob) == iso8583::OK { set_count += 1; }
    }
    bad += check(set_count == 65, "65 fields fill the buffer");
    bad += check(z.live == 65 * 999, "live holds at the fill");
    // Unset a field in the middle: a hole of zeros, live drops.
    bad += check(iso8583::message_unset(z, 50) == iso8583::OK, "unset a middle field");
    bad += check(z.holes == 1, "a hole appears");
    bad += check(z.live == 64 * 999, "live drops by 999");
    // The same field again: the buffer would pass its limit, so one
    // compaction makes room and the set succeeds.
    bad += check(iso8583::message_set(z, big, 50, blob) == iso8583::OK, "set after compaction");
    bad += check(z.holes == 0, "the compaction cleared the holes");
    bad += check(z.data.len <= 65535, "the buffer holds the limit");
    bad += check(z.live == 65 * 999, "live holds after compaction");
    return bad;
}

// The sum of the lengths of the present slots.
fn sum_lens(m: iso8583::Message&) -> i64 {
    var t: i64 = 0;
    for id in 2..193 {
        if m.slots[id].present { t += m.slots[id].len; }
    }
    return t;
}

// A compaction moves the fields to the front. The bytes of every
// field must stay the same. A small hole before a big field gives the
// copy an overlap.
fn run_message_compact() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    for fid in 48..116 {
        iso8583::dialect_field(d, fid, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII,
                               iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    }
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    var big: u8[>..] = [];
    for i in 0..999 { big.push('b'); }
    var mid: u8[>..] = [];
    for i in 0..600 { mid.push('m'); }
    // A small field at the front, then 64 fields of 999 bytes.
    bad += check(iso8583::message_set(m, d, 48, "A") == iso8583::OK, "set the small field");
    for fid in 49..114 {
        if fid == 65 { continue; }
        iso8583::message_set(m, d, fid, big);
    }
    bad += check(iso8583::message_set(m, d, 114, mid) == iso8583::OK, "set the middle field");
    bad += check(m.live == 64537, "the fill holds the live bytes");
    // Drop the small field: the hole of one byte sits before a field of
    // 999 bytes.
    bad += check(iso8583::message_unset(m, 48) == iso8583::OK, "unset the small field");
    bad += check(m.holes == 1, "the hole counts");
    bad += check(m.data.len == 64537, "the buffer keeps the hole");
    // The new field does not fit, so the message compacts.
    bad += check(iso8583::message_set(m, d, 115, big) == iso8583::OK, "set after the compaction");
    bad += check(m.data.len == 65535 && m.live == 65535, "the compaction fills the buffer");
    bad += check(m.holes == 0, "the compaction clears the holes");
    // Every value of a moved field is the same.
    var got: u8[>..] = [];
    bad += check(iso8583::message_get(m, 49, got) == iso8583::OK && same(got, big), "the moved field keeps its bytes");
    got.clear();
    bad += check(iso8583::message_get(m, 112, got) == iso8583::OK && same(got, big), "the second field keeps its bytes");
    got.clear();
    bad += check(iso8583::message_get(m, 114, got) == iso8583::OK && same(got, mid), "the middle field keeps its bytes");
    got.clear();
    bad += check(iso8583::message_get(m, 115, got) == iso8583::OK && same(got, big), "the new field keeps its bytes");
    // The stale bytes of the hole are gone.
    var stale = 0;
    for i in 0..m.data.len {
        if m.data[i] == 'A' { stale += 1; }
    }
    bad += check(stale == 0, "the stale bytes of the hole are gone");
    return bad;
}

// The buffer holds the fields in the order they were set. A compaction
// must move them in that order, not in the order of the field ids.
fn run_message_order() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 3);
    for id in 2..82 {
        iso8583::dialect_field(d, id, iso8583::KIND_LLLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII,
                               iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    }
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    var big: u8[>..] = [];
    for i in 0..999 { big.push('b'); }
    var b20: u8[>..] = [];
    for i in 0..999 { b20.push('2'); }
    var b5: u8[>..] = [];
    for i in 0..999 { b5.push('5'); }
    // A higher id first, then a lower id: the order of the offsets
    // differs from the order of the ids.
    bad += check(iso8583::message_set(m, d, 20, b20) == iso8583::OK, "set the higher id");
    bad += check(iso8583::message_set(m, d, 5, b5) == iso8583::OK, "set the lower id");
    for id in 2..82 {
        if id == 5 || id == 20 { continue; }
        iso8583::message_set(m, d, id, big);
    }
    // Shrink field 20: the freed bytes leave a hole.
    var small: u8[>..] = [];
    for i in 0..500 { small.push('9'); }
    bad += check(iso8583::message_set(m, d, 20, small) == iso8583::OK, "shrink field 20");
    bad += check(m.holes == 1, "the shrink leaves a hole");
    // The next set does not fit, so the message compacts.
    bad += check(iso8583::message_set(m, d, 20, b20) == iso8583::OK, "grow field 20");
    // Both values are the same after the compaction.
    var got: u8[>..] = [];
    bad += check(iso8583::message_get(m, 5, got) == iso8583::OK && same(got, b5), "field 5 keeps its value");
    got.clear();
    bad += check(iso8583::message_get(m, 20, got) == iso8583::OK && same(got, b20), "field 20 keeps its value");
    // The wire form holds the same bytes.
    var out: u8[>..] = [];
    bad += check(iso8583::pack(out, m, d) == iso8583::OK, "pack");
    var m2 = iso8583::Message { .. };
    bad += check(iso8583::unpack(m2, d, out) == iso8583::OK, "unpack");
    got.clear();
    bad += check(iso8583::message_get(m2, 5, got) == iso8583::OK && same(got, b5), "field 5 on the wire");
    got.clear();
    bad += check(iso8583::message_get(m2, 20, got) == iso8583::OK && same(got, b20), "field 20 on the wire");
    return bad;
}

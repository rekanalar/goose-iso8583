namespace suite;

import std;
import iso8583 from "../..";
import util;
import tlv_cases;

// A seeded byte generator: one stream of hostile bytes, same on every run.
fn rand_bytes(out: u8[>..]&, seed: i64, n: i64) {
    var s = seed;
    for i in 0..n {
        s = (s * 1103515245 + 12345) % 2147483648;
        out.push((s / 65536) as u8);
    }
}

// Hostile TLV: every cut, every flip and 100000 random payloads.
fn hostile_tlv() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    ber_dialect(d, "9F26:00,95:00,5F2A:00");
    var msg = iso8583::Message { .. };
    var wire: u8[>..] = [];
    for c in 0..tlv_count() {
        from_hex(wire, tlv_payload(c));
        // Every cut of every sample.
        for cut in 0..wire.len {
            let piece = wire[0..cut];
            var full: u8[>..] = [];
            full.append("010000000000000200");
            format_int(full, piece.len, 10, 3, '0');
            full.append(piece);
            let f = iso8583::unpack(msg, d, full);
            bad += check(f == iso8583::OK || (f >= 1 && f <= 18), "tlv cut returns a code");
            bad += check(msg.mti.len == 0 || f == iso8583::OK, "tlv cut empties the message");
        }
        // Every bit of every byte.
        for bi in 0..wire.len {
            for bit in 0..8 {
                var flip: u8[>..] = [];
                flip.append(wire);
                flip[bi] = flip[bi] ^ ((1 as u8) << bit);
                var full: u8[>..] = [];
                full.append("010000000000000200");
                format_int(full, flip.len, 10, 3, '0');
                full.append(flip);
                let f = iso8583::unpack(msg, d, full);
                bad += check(f == iso8583::OK || (f >= 1 && f <= 18), "tlv flip returns a code");
                bad += check(msg.mti.len == 0 || f == iso8583::OK, "tlv flip empties the message");
            }
        }
    }
    // 100000 random payloads.
    var rnd: u8[>..] = [];
    for i in 0..100000 {
        rnd.clear();
        rand_bytes(rnd, 8583 + i, (i % 40) + 1);
        var full: u8[>..] = [];
        full.append("010000000000000200");
        format_int(full, rnd.len, 10, 3, '0');
        full.append(rnd);
        let f = iso8583::unpack(msg, d, full);
        bad += check(f == iso8583::OK || (f >= 1 && f <= 18), "tlv random returns a code");
        if f != iso8583::OK { bad += check(msg.mti.len == 0, "tlv random empties the message"); }
    }
    return bad;
}

// Hostile track text.
fn hostile_track() -> i64 {
    var bad = 0;
    var t = iso8583::Track { .. };
    var sample: u8[>..] = [];
    sample.append("4000000000000001=25121010000000");
    for cut in 0..sample.len {
        bad += check(iso8583::track2_parse(t, sample[0..cut]) == iso8583::OK || iso8583::track2_parse(t, sample[0..cut]) == iso8583::ERR_BAD_TRACK, "track cut");
    }
    for bi in 0..sample.len {
        for bit in 0..8 {
            var flip: u8[>..] = [];
            flip.append(sample);
            flip[bi] = flip[bi] ^ ((1 as u8) << bit);
            let f = iso8583::track2_parse(t, flip);
            bad += check(f == iso8583::OK || f == iso8583::ERR_BAD_TRACK, "track flip");
            if f == iso8583::ERR_BAD_TRACK { bad += check(t.pan.len == 0, "track fault carries no bytes"); }
        }
    }
    var rnd: u8[>..] = [];
    for i in 0..100000 {
        rnd.clear();
        rand_bytes(rnd, 1234 + i, (i % 45) + 1);
        let f = iso8583::track2_parse(t, rnd);
        bad += check(f == iso8583::OK || f == iso8583::ERR_BAD_TRACK, "track random");
        if f == iso8583::ERR_BAD_TRACK { bad += check(t.pan.len == 0, "track random carries no bytes"); }
        let f1 = iso8583::track1_parse(t, rnd);
        bad += check(f1 == iso8583::OK || f1 == iso8583::ERR_BAD_TRACK, "track1 random");
    }
    return bad;
}

// Hostile stream input.
fn hostile_stream() -> i64 {
    var bad = 0;
    for h in 1..4 {
        var frame: u8[>..] = [];
        iso8583::frame_write(frame, h, "sample body");
        for cut in 0..frame.len {
            var r = iso8583::Reader { .. };
            iso8583::reader_init(r, h);
            let piece = frame[0..cut];
            let used, f = iso8583::reader_feed(r, piece);
            bad += check(f == iso8583::OK || (f >= 1 && f <= 18), "stream cut");
            if f != iso8583::OK { bad += check(r.state == iso8583::STATE_FAULT && r.buf.len == 0, "stream fault clears"); }
        }
        for bi in 0..frame.len {
            for bit in 0..8 {
                var flip: u8[>..] = [];
                flip.append(frame);
                flip[bi] = flip[bi] ^ ((1 as u8) << bit);
                var r = iso8583::Reader { .. };
                iso8583::reader_init(r, h);
                let used, f = iso8583::reader_feed(r, flip);
                bad += check(f == iso8583::OK || (f >= 1 && f <= 18), "stream flip");
                if f != iso8583::OK { bad += check(r.buf.len == 0, "stream flip clears"); }
            }
        }
    }
    var rnd: u8[>..] = [];
    for i in 0..100000 {
        rnd.clear();
        rand_bytes(rnd, 555 + i, (i % 20) + 1);
        var r = iso8583::Reader { .. };
        iso8583::reader_init(r, iso8583::HEADER_ASCII4);
        let used, f = iso8583::reader_feed(r, rnd);
        bad += check(f == iso8583::OK || (f >= 1 && f <= 18), "stream random");
        bad += check(r.buf.len <= iso8583::MAX_BUFFER, "stream random bounded");
    }
    return bad;
}

// No fault ever echoes a value byte or a tag byte, and the text form of
// a track, a PAN and a TLV value never holds eleven digits in a row.
fn hostile_no_echo() -> i64 {
    var bad = 0;
    let marker = "4111111111111111";
    var d = iso8583::Dialect { .. };
    ber_dialect(d, "9F26:00,95:00,5F2A:00");
    // Force every TLV fault with a marker in the values and the tags.
    let hexes: const u8[:][12] = [
        "9502000411111111111111",
        "9A0241111111111111",
        "9F2606000000000000",
        "9F2605",
        "9F26",
        "9F2610",
        "958105000000000000",
        "9580",
        "958300000500000000",
        "9FA8A813",
        "9502000411111111111111",
        "9501",
    ];
    var msg = iso8583::Message { .. };
    var text: u8[>..] = [];
    for i in 0..12 {
        var p: u8[>..] = [];
        from_hex(p, hexes[i]);
        var full: u8[>..] = [];
        full.append("010000000000000200");
        format_int(full, p.len, 10, 3, '0');
        full.append(p);
        iso8583::unpack(msg, d, full);
        iso8583::message_text(text, msg, d);
        bad += check(!has_run(text, marker), "no marker in the fault text");
        bad += check(!has_run(text, "9F26"), "no tag bytes in the fault text");
    }
    return bad;
}

// The full text form of a message with a track, a PAN and a TLV subfield
// never holds a run of eleven digits of the card number.
fn hostile_windows() -> i64 {
    var bad = 0;
    let pan = "4000001234567890";
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_BER, 0);
    iso8583::dialect_sub(d, iso8583::path1(55), 0x9F26, iso8583::KIND_LLVAR, iso8583::ENC_ASCII, iso8583::ENC_ASCII, iso8583::UNIT_BYTES, 19, iso8583::PAD_LEFT, iso8583::MASK_PAN);
    iso8583::dialect_sub(d, iso8583::path1(55), 0x95, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    bad += check(iso8583::message_set(m, d, 2, pan) == iso8583::OK, "set pan");
    var tr: u8[>..] = [];
    tr.append(pan);
    tr.append("=2512");
    bad += check(iso8583::message_set(m, d, 35, tr) == iso8583::OK, "set track");
    tr.clear();
    tr.push('B');
    tr.append(pan);
    tr.append("^AB^2512101D");
    bad += check(iso8583::message_set(m, d, 45, tr) == iso8583::OK, "set track1");
    var payload: u8[>..] = [];
    payload.push(0x9F); payload.push(0x26); payload.push(0x10);
    payload.append(pan);
    payload.push(0x95); payload.push(0x02);
    payload.append("OK");
    bad += check(iso8583::message_set(m, d, 55, payload) == iso8583::OK, "set tlv");
    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);
    // No window of eleven digits of the pan.
    for i in 0..6 {
        var win: u8[>..] = [];
        win.append(pan[i..i + 11]);
        bad += check(!has_run(text, win), "window hidden");
    }
    // The full pan and the track parts.
    bad += check(!has_run(text, pan), "pan hidden");
    bad += check(!has_run(text, "4000001234567890=2512"), "track hidden");
    return bad;
}

fn run_hostile2() -> i64 {
    var bad = 0;
    bad += hostile_tlv();
    bad += hostile_track();
    bad += hostile_stream();
    bad += hostile_no_echo();
    bad += hostile_windows();
    return bad;
}

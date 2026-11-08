namespace suite;

import std;
import iso8583 from "../..";
import util;

// True when the text holds a run of 11 digits.
fn has_11_digits(text: const u8[:]) -> bool {
    var run = 0;
    for i in 0..text.len {
        if text[i] >= '0' && text[i] <= '9' {
            run += 1;
            if run >= 11 { return true; }
        } else {
            run = 0;
        }
    }
    return false;
}

// True when the text holds the part as a run of bytes.
fn has_part(text: const u8[:], part: const u8[:]) -> bool {
    return has_run(text, part);
}

// One valid track 2: the parts must be right and the build must give
// the same text back.
fn track2_ok(text: const u8[:], pan: const u8[:], expiry: const u8[:], service: const u8[:], disc: const u8[:], what: const u8[:]) -> i64 {
    var bad = 0;
    var t = iso8583::Track { .. };
    bad += check(iso8583::track2_parse(t, text) == iso8583::OK, what);
    bad += eq_bytes(t.pan, pan, what);
    bad += eq_bytes(t.expiry, expiry, what);
    bad += eq_bytes(t.service, service, what);
    bad += eq_bytes(t.discretionary, disc, what);
    var out: u8[>..] = [];
    bad += check(iso8583::track2_build(out, t) == iso8583::OK, what);
    bad += eq_bytes(out, text, what);
    return bad;
}

// One valid track 1: the parts must be right and the build must give
// the same text back.
fn track1_ok(text: const u8[:], pan: const u8[:], name: const u8[:], expiry: const u8[:], service: const u8[:], disc: const u8[:], what: const u8[:]) -> i64 {
    var bad = 0;
    var t = iso8583::Track { .. };
    bad += check(iso8583::track1_parse(t, text) == iso8583::OK, what);
    bad += eq_bytes(t.pan, pan, what);
    bad += eq_bytes(t.name, name, what);
    bad += eq_bytes(t.expiry, expiry, what);
    bad += eq_bytes(t.service, service, what);
    bad += eq_bytes(t.discretionary, disc, what);
    var out: u8[>..] = [];
    bad += check(iso8583::track1_build(out, t) == iso8583::OK, what);
    bad += eq_bytes(out, text, what);
    return bad;
}

// A track that breaks a rule gives ERR_BAD_TRACK and leaves the track
// empty.
fn track_bad_text(text: const u8[:], what: const u8[:]) -> i64 {
    var bad = 0;
    var t = iso8583::Track { .. };
    bad += check(iso8583::track2_parse(t, text) == iso8583::ERR_BAD_TRACK, what);
    bad += check(t.pan.len == 0 && t.expiry.len == 0 && t.service.len == 0 && t.discretionary.len == 0, what);
    var t2 = iso8583::Track { .. };
    bad += check(iso8583::track1_parse(t2, text) == iso8583::ERR_BAD_TRACK, what);
    bad += check(t2.pan.len == 0 && t2.name.len == 0 && t2.expiry.len == 0 && t2.service.len == 0 && t2.discretionary.len == 0, what);
    return bad;
}

fn run_track() -> i64 {
    var bad = 0;
    // Valid track 2 values.
    bad += track2_ok("4000000000000001=25121010000000", "4000000000000001", "2512", "101", "0000000", "track2 full");
    bad += track2_ok("4000000000000001D2512101", "4000000000000001", "2512", "101", "", "track2 D separator");
    bad += track2_ok("4000000000000001=2512101", "4000000000000001", "2512", "101", "", "track2 no discretionary");
    bad += track2_ok("4=2512101", "4", "2512", "101", "", "track2 one digit pan");
    bad += track2_ok("4000000000000000009=2512101", "4000000000000000009", "2512", "101", "", "track2 nineteen digits");
    // Valid track 1 values.
    bad += track1_ok("B4000000000000001^CARDHOLDER^25121010000000", "4000000000000001", "CARDHOLDER", "2512", "101", "0000000", "track1 full");
    bad += track1_ok("B4000000000000001^AB^^^", "4000000000000001", "AB", "", "", "", "track1 no expiry and service");
    bad += track1_ok("B4000000000000001^AB^2512101D", "4000000000000001", "AB", "2512", "101", "D", "track1 discretionary");
    bad += track1_ok("B4000000000000001^ABCDEFGHIJKLMNOPQRSTUVWXYZ^2512101", "4000000000000001", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "2512", "101", "", "track1 name of 26");
    // Faults.
    bad += track_bad_text("40000000000000000009=2512101", "track2 twenty digits");
    bad += track_bad_text("400000000000000X=2512101", "track2 letter in the pan");
    bad += track_bad_text("4000000000000001 2512101", "track2 missing separator");
    bad += track_bad_text("4000000000000001=251", "track2 short expiry");
    bad += track_bad_text("4000000000000001=2512101%", "track2 percent at the end");
    bad += track_bad_text("4000000000000001=2512101?", "track2 question at the end");
    bad += track_bad_text("B4000000000000001^CARDHOLDER^2512", "track1 missing the second separator");
    bad += track_bad_text("B4000000000000001^A^2512101", "track1 short name");
    bad += track_bad_text("B4000000000000001^ABCDEFGHIJKLMNOPQRSTUVWXYZ1^2512101", "track1 long name");
    bad += track_bad_text("B4000000000000001^CARD^HOLDER^2512101", "track1 name with a separator");
    bad += track_bad_text("B4000000000000001^CARDHOLDER^251", "track1 short expiry");
    bad += track_bad_text("B4000000000000001^CARDHOLDER^2512101%X", "track1 percent in the discretionary");
    bad += track_bad_text("B4000000000000001^CARDHOLDER^^", "track1 no expiry and no service");
    bad += track_bad_text("4000000000000001", "track2 without the separator");
    bad += track_bad_text("", "empty track");
    bad += track_bad_text("b4000000000000001^CARDHOLDER^2512101", "track1 lower case format code");
    // A track 2 value of more than 40 discretionary bytes.
    var long: u8[>..] = [];
    long.append("4000000000000001=2512101");
    for i in 0..41 { long.push('0'); }
    bad += track_bad_text(long, "track2 discretionary above the limit");
    // The text form of a message with a track stays masked.
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    bad += check(iso8583::message_set(m, d, 35, "4000000000000001=25121010000000") == iso8583::OK, "set track 2");
    bad += check(iso8583::message_set(m, d, 45, "B4000000000000001^CARDHOLDER^25121010000000") == iso8583::OK, "set track 1");
    var text: u8[>..] = [];
    bad += check(iso8583::message_text(text, m, d) == iso8583::OK, "text");
    bad += check(!has_11_digits(text), "no run of eleven digits");
    bad += check(!has_part(text, "4000000000000001"), "no pan in the text");
    bad += check(!has_part(text, "CARDHOLDER"), "no name in the text");
    bad += check(has_part(text, "F035 ["), "field 35 line");
    bad += check(has_part(text, "F045 ["), "field 45 line");
    return bad;
}

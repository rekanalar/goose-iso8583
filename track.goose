// The magnetic stripe track data of a card. A track 2 holds the PAN,
// the expiry, the service code and the discretionary data. A track 1
// holds the format code, the PAN, the name, the expiry, the service code
// and the discretionary data.
//
// Every part has a bound. A text that breaks a rule gives
// ERR_BAD_TRACK, and the track stays empty, so a fault never carries
// track bytes.
namespace iso8583;

import std;

// The longest discretionary part of a track 1 and of a track 2.
const TRACK1_DISC: i64 = 79;
const TRACK2_DISC: i64 = 40;

// Empties a track.
fn track_clear(t: Track&) {
    t.kind = 0;
    t.has_expiry = false;
    t.has_service = false;
    t.format.clear();
    t.pan.clear();
    t.name.clear();
    t.expiry.clear();
    t.service.clear();
    t.discretionary.clear();
}

// True when the byte is a digit.
// True when the byte may not appear in a track: the two sentinels that
// mark the end of a track in some readers.
fn track_bad(c: u8) -> bool {
    return c == '?' || c == '%';
}

// Reads the digits of the PAN at pos. Returns the new position and a
// fault code.
fn track_pan(t: Track&, text: const u8[:], pos: i64) -> i64, i64 {
    let start = pos;
    var end = pos;
    while end < text.len && is_digit(text[end]) { end += 1; }
    let n = end - start;
    if n < 1 || n > 19 { return end, ERR_BAD_TRACK; }
    t.pan.append(text[start..end]);
    return end, OK;
}

// Reads the digits of a part of a fixed count at pos. Returns the new
// position and a fault code.
fn track_digits(out: u8[>..]&, text: const u8[:], pos: i64, count: i64) -> i64, i64 {
    if pos + count > text.len { return pos, ERR_BAD_TRACK; }
    for i in 0..count {
        if !is_digit(text[pos + i]) { return pos, ERR_BAD_TRACK; }
    }
    out.append(text[pos..pos + count]);
    return pos + count, OK;
}

// Parses a track 2 string: the PAN, the separator, the expiry, the
// service code and the discretionary data.
fn track2_parse(t: Track&, text: const u8[:]) -> i64 {
    track_clear(t);
    if text.len < 1 { return ERR_BAD_TRACK; }
    var pos: i64 = 0;
    let p, f = track_pan(t, text, pos);
    if f != OK { track_clear(t); return f; }
    pos = p;
    if pos >= text.len { track_clear(t); return ERR_BAD_TRACK; }
    let sep = text[pos];
    if sep != '=' && sep != 'D' { track_clear(t); return ERR_BAD_TRACK; }
    t.format.clear();
    t.format.push(sep);
    pos += 1;
    var expiry: u8[>..] = [];
    let e, f2 = track_digits(expiry, text, pos, 4);
    if f2 != OK { track_clear(t); return f2; }
    pos = e;
    t.expiry.append(expiry);
    t.has_expiry = true;
    var service: u8[>..] = [];
    let s, f3 = track_digits(service, text, pos, 3);
    if f3 != OK { track_clear(t); return f3; }
    pos = s;
    t.service.append(service);
    t.has_service = true;
    let d = text.len - pos;
    if d > TRACK2_DISC { track_clear(t); return ERR_BAD_TRACK; }
    for i in pos..text.len {
        if track_bad(text[i]) { track_clear(t); return ERR_BAD_TRACK; }
    }
    t.discretionary.append(text[pos..text.len]);
    t.kind = 2;
    return OK;
}

// Parses a track 1 string in format B: the format code, the PAN, the
// name, the expiry, the service code and the discretionary data.
fn track1_parse(t: Track&, text: const u8[:]) -> i64 {
    track_clear(t);
    if text.len < 1 { return ERR_BAD_TRACK; }
    let code = text[0];
    if code < 'A' || code > 'Z' { track_clear(t); return ERR_BAD_TRACK; }
    t.format.clear();
    t.format.push(code);
    var pos: i64 = 1;
    let p, f = track_pan(t, text, pos);
    if f != OK { track_clear(t); return f; }
    pos = p;
    if pos >= text.len || text[pos] != '^' { track_clear(t); return ERR_BAD_TRACK; }
    pos += 1;
    // The name runs to the next separator.
    var start = pos;
    while pos < text.len && text[pos] != '^' { pos += 1; }
    let n = pos - start;
    if n < 2 || n > 26 { track_clear(t); return ERR_BAD_TRACK; }
    t.name.append(text[start..pos]);
    if pos >= text.len { track_clear(t); return ERR_BAD_TRACK; }
    pos += 1;
    // The expiry is four digits, or one caret when it is not there.
    if pos < text.len && text[pos] == '^' {
        pos += 1;
        t.has_expiry = false;
    } else {
        var expiry: u8[>..] = [];
        let e, f2 = track_digits(expiry, text, pos, 4);
        if f2 != OK { track_clear(t); return f2; }
        pos = e;
        t.expiry.append(expiry);
        t.has_expiry = true;
    }
    // The service code is three digits, or one caret when it is not there.
    if pos < text.len && text[pos] == '^' {
        pos += 1;
        t.has_service = false;
    } else {
        var service: u8[>..] = [];
        let s, f3 = track_digits(service, text, pos, 3);
        if f3 != OK { track_clear(t); return f3; }
        pos = s;
        t.service.append(service);
        t.has_service = true;
    }
    let d = text.len - pos;
    if d > TRACK1_DISC { track_clear(t); return ERR_BAD_TRACK; }
    for i in pos..text.len {
        if track_bad(text[i]) { track_clear(t); return ERR_BAD_TRACK; }
    }
    t.discretionary.append(text[pos..text.len]);
    t.kind = 1;
    return OK;
}

// Builds a track 2 string from the parts. out is empty on a fault.
fn track2_build(out: u8[>..]&, t: Track&) -> i64 {
    out.clear();
    if t.kind != 2 { return ERR_BAD_TRACK; }
    if t.pan.len < 1 || t.pan.len > 19 { return ERR_BAD_TRACK; }
    if t.format.len != 1 { return ERR_BAD_TRACK; }
    if t.format[0] != '=' && t.format[0] != 'D' { return ERR_BAD_TRACK; }
    if t.expiry.len != 4 || t.service.len != 3 { return ERR_BAD_TRACK; }
    if t.discretionary.len > TRACK2_DISC { return ERR_BAD_TRACK; }
    out.append(t.pan);
    out.push(t.format[0]);
    out.append(t.expiry);
    out.append(t.service);
    out.append(t.discretionary);
    return OK;
}

// Builds a track 1 string from the parts. out is empty on a fault.
fn track1_build(out: u8[>..]&, t: Track&) -> i64 {
    out.clear();
    if t.kind != 1 { return ERR_BAD_TRACK; }
    if t.format.len != 1 { return ERR_BAD_TRACK; }
    if t.format[0] < 'A' || t.format[0] > 'Z' { return ERR_BAD_TRACK; }
    if t.pan.len < 1 || t.pan.len > 19 { return ERR_BAD_TRACK; }
    if t.name.len < 2 || t.name.len > 26 { return ERR_BAD_TRACK; }
    if t.discretionary.len > TRACK1_DISC { return ERR_BAD_TRACK; }
    for i in 0..t.name.len {
        if t.name[i] == '^' { return ERR_BAD_TRACK; }
    }
    out.append(t.format);
    out.append(t.pan);
    out.push('^');
    out.append(t.name);
    out.push('^');
    if t.has_expiry {
        if t.expiry.len != 4 { return ERR_BAD_TRACK; }
        out.append(t.expiry);
    } else {
        out.push('^');
    }
    if t.has_service {
        if t.service.len != 3 { return ERR_BAD_TRACK; }
        out.append(t.service);
    } else {
        out.push('^');
    }
    out.append(t.discretionary);
    return OK;
}

namespace suite;

import std;
import iso8583 from "../..";
import util;

// Feeds the stream to the reader in pieces of the given sizes (cycling)
// and collects each body, joined by '|'. Returns the fault code.
fn feed_all(r: iso8583::Reader&, stream: const u8[:], pieces: const i64[:], out: u8[>..]&) -> i64 {
    var pos = 0;
    var pi = 0;
    var body: u8[>..] = [];
    while pos < stream.len {
        var n = pieces[pi % pieces.len];
        pi += 1;
        if n < 1 { n = 1; }
        if pos + n > stream.len { n = stream.len - pos; }
        var cstart = pos;
        var clen = n;
        pos += n;
        while clen > 0 {
            let chunk = stream[cstart..cstart + clen];
            let used, f = iso8583::reader_feed(r, chunk);
            if f != iso8583::OK { return f; }
            cstart += used;
            clen -= used;
            if iso8583::reader_ready(r) {
                if iso8583::reader_take(r, body) != iso8583::OK { return iso8583::ERR_BAD_ARG; }
                if out.len > 0 { out.push('|'); }
                out.append(body);
            }
            if used == 0 && !iso8583::reader_ready(r) { break; }
        }
    }
    return iso8583::OK;
}

// A split case: two framed bodies, fed in the given piece sizes.
fn split_case(header: i64, pieces: const i64[:], what: const u8[:]) -> i64 {
    var bad = 0;
    var a: u8[>..] = [];
    var b: u8[>..] = [];
    var stream: u8[>..] = [];
    bad += check(iso8583::frame_write(a, header, "first message") == iso8583::OK, what);
    bad += check(iso8583::frame_write(b, header, "second") == iso8583::OK, what);
    stream.append(a);
    stream.append(b);
    var r = iso8583::Reader { .. };
    bad += check(iso8583::reader_init(r, header) == iso8583::OK, what);
    var out: u8[>..] = [];
    bad += check(feed_all(r, stream, pieces, out) == iso8583::OK, what);
    bad += eq_bytes(out, "first message|second", what);
    return bad;
}

fn run_stream() -> i64 {
    var bad = 0;
    let one: i64[1] = [1];
    let all: i64[1] = [100000];
    let seven: i64[1] = [7];
    let mixed: i64[5] = [3, 1, 11, 2, 5];
    for h in 1..4 {
        bad += split_case(h, one, "one byte at a time");
        bad += split_case(h, all, "one block");
        bad += split_case(h, seven, "pieces of seven");
        bad += split_case(h, mixed, "mixed pieces");
    }
    // Split the stream at every offset into two calls.
    for h in 1..4 {
        var a: u8[>..] = [];
        var b: u8[>..] = [];
        var stream: u8[>..] = [];
        iso8583::frame_write(a, h, "first message");
        iso8583::frame_write(b, h, "second");
        stream.append(a);
        stream.append(b);
        for cut in 1..stream.len {
            var r = iso8583::Reader { .. };
            iso8583::reader_init(r, h);
            var out: u8[>..] = [];
            let pcs: i64[2] = [cut, 100000];
            bad += check(feed_all(r, stream, pcs, out) == iso8583::OK, "cut");
            bad += eq_bytes(out, "first message|second", "cut result");
        }
    }
    // Two messages and half of a third in one call: the reader stops at the end of each frame.
    {
        var a: u8[>..] = [];
        var s: u8[>..] = [];
        iso8583::frame_write(a, iso8583::HEADER_ASCII4, "one");
        s.append(a);
        iso8583::frame_write(a, iso8583::HEADER_ASCII4, "two");
        s.append(a);
        iso8583::frame_write(a, iso8583::HEADER_ASCII4, "three");
        s.append(a[0..6]);
        var r = iso8583::Reader { .. };
        iso8583::reader_init(r, iso8583::HEADER_ASCII4);
        let n1, f1 = iso8583::reader_feed(r, s);
        bad += check(f1 == iso8583::OK && iso8583::reader_ready(r) && n1 == 7, "stops after the first frame");
        var body: u8[>..] = [];
        bad += check(iso8583::reader_take(r, body) == iso8583::OK, "take first");
        bad += eq_bytes(body, "one", "first body");
        let rest2 = s[n1..s.len];
        let n2, f2 = iso8583::reader_feed(r, rest2);
        bad += check(f2 == iso8583::OK && iso8583::reader_ready(r) && n2 == 7, "stops after the second frame");
        iso8583::reader_take(r, body);
        bad += eq_bytes(body, "two", "second body");
        let rest = s[n1 + n2..s.len];
        let n3, f3 = iso8583::reader_feed(r, rest);
        bad += check(f3 == iso8583::OK && !iso8583::reader_ready(r) && n3 == 6, "half of a third stays unready");
        // take with nothing waiting
        bad += check(iso8583::reader_take(r, body) == iso8583::ERR_NOT_SET, "take without a body");
    }
    // A header of length zero gives an empty body.
    for h in 1..4 {
        var a: u8[>..] = [];
        iso8583::frame_write(a, h, "");
        var r = iso8583::Reader { .. };
        iso8583::reader_init(r, h);
        let n, f = iso8583::reader_feed(r, a);
        bad += check(f == iso8583::OK && iso8583::reader_ready(r) && n == a.len, "empty body is ready");
        var body: u8[>..] = [];
        bad += check(iso8583::reader_take(r, body) == iso8583::OK && body.len == 0, "empty body");
    }
    // HEADER_NONE cannot be split.
    {
        var r = iso8583::Reader { .. };
        bad += check(iso8583::reader_init(r, iso8583::HEADER_NONE) == iso8583::ERR_BAD_ARG, "none rejected");
        bad += check(iso8583::reader_init(r, 9) == iso8583::ERR_BAD_ARG, "unknown kind rejected");
    }
    bad += run_stream_faults();
    bad += run_stream_bound();
    return bad;
}

// A run of hostile bytes must never push the buffer over its limit.
// The stream is framed properly, so the run ends clean.
fn run_stream_bound() -> i64 {
    var bad = 0;
    // One frame of a legal maximum, fed in blocks of 70000 bytes.
    var a: u8[>..] = [];
    var big: u8[>..] = [];
    for i in 0..30000 { big.push((i % 251) as u8); }
    iso8583::frame_write(a, iso8583::HEADER_BINARY2, big);
    var r = iso8583::Reader { .. };
    iso8583::reader_init(r, iso8583::HEADER_BINARY2);
    var pos = 0;
    while pos < a.len {
        var end = pos + 70000;
        if end > a.len { end = a.len; }
        let blk = a[pos..end];
        let used, f = iso8583::reader_feed(r, blk);
        bad += check(f == iso8583::OK, "big frame feed");
        pos += used;
        if used == 0 && !iso8583::reader_ready(r) { break; }
    }
    bad += check(iso8583::reader_ready(r), "big frame ready");
    var body: u8[>..] = [];
    bad += check(iso8583::reader_take(r, body) == iso8583::OK, "big frame take");
    bad += eq_bytes(body, big, "big frame body");
    bad += check(r.buf.len == 0, "buffer emptied after take");
    // The largest header of each kind is the limit of that kind, so the
    // reader takes it. A header that is not a number faults before any
    // body byte is stored.
    var over: u8[>..] = [];
    from_hex(over, "FFFF");
    over.append("junk that never gets stored");
    var r2 = iso8583::Reader { .. };
    iso8583::reader_init(r2, iso8583::HEADER_BINARY2);
    let n2, f2 = iso8583::reader_feed(r2, over);
    bad += check(f2 == iso8583::OK, "the largest header is legal");
    bad += check(!iso8583::reader_ready(r2), "the body is not whole yet");
    bad += check(r2.buf.len == over.len - 2, "only the bytes that arrived are kept");
    var r4 = iso8583::Reader { .. };
    iso8583::reader_init(r4, iso8583::HEADER_ASCII4);
    let n4, f4 = iso8583::reader_feed(r4, "999xbody");
    bad += check(f4 == iso8583::ERR_BAD_LENGTH, "a letter in the header faults");
    bad += check(r4.buf.len == 0, "no body byte stored");
    // One million hostile bytes in blocks, with a clean exit either way.
    var junk: u8[>..] = [];
    var seed: i64 = 12345;
    for i in 0..1000000 {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        junk.push((seed % 256) as u8);
    }
    var r3 = iso8583::Reader { .. };
    iso8583::reader_init(r3, iso8583::HEADER_ASCII4);
    var pos3 = 0;
    while pos3 < junk.len && r3.state != iso8583::STATE_FAULT {
        var end = pos3 + 65543;
        if end > junk.len { end = junk.len; }
        let blk = junk[pos3..end];
        let used, f = iso8583::reader_feed(r3, blk);
        bad += check(f == iso8583::OK || f == iso8583::ERR_TOO_LONG || f == iso8583::ERR_BAD_LENGTH || f == iso8583::ERR_STREAM, "hostile feed returns a code");
        if f != iso8583::OK { break; }
        pos3 += used;
        if iso8583::reader_ready(r3) {
            var b: u8[>..] = [];
            iso8583::reader_take(r3, b);
        }
        if used == 0 { break; }
    }
    bad += check(r3.buf.len <= iso8583::MAX_BUFFER, "buffer within the limit");
    return bad;
}

// Feeds one stream and expects a fault, then a lock, then a reset.
fn fault_case(header: i64, stream: const u8[:], want: i64, what: const u8[:]) -> i64 {
    var bad = 0;
    var r = iso8583::Reader { .. };
    iso8583::reader_init(r, header);
    let n, f = iso8583::reader_feed(r, stream);
    bad += check(f == want, what);
    bad += check(r.buf.len == 0, what);
    // The reader stays locked.
    let n2, f2 = iso8583::reader_feed(r, "0003abc");
    bad += check(f2 == iso8583::ERR_STREAM && n2 == 0, what);
    var body: u8[>..] = [];
    bad += check(iso8583::reader_take(r, body) == iso8583::ERR_STREAM, what);
    iso8583::reader_reset(r);
    var ok: u8[>..] = [];
    iso8583::frame_write(ok, header, "abc");
    let n3, f3 = iso8583::reader_feed(r, ok);
    bad += check(f3 == iso8583::OK && iso8583::reader_ready(r), what);
    return bad;
}

fn run_stream_faults() -> i64 {
    var bad = 0;
    var raw: u8[>..] = [];
    bad += fault_case(iso8583::HEADER_ASCII4, "00x3abc", iso8583::ERR_BAD_LENGTH, "letter in the header");
    bad += fault_case(iso8583::HEADER_ASCII4, "-123abc", iso8583::ERR_BAD_LENGTH, "sign in the header");
    bad += fault_case(iso8583::HEADER_ASCII4, "+123abc", iso8583::ERR_BAD_LENGTH, "plus in the header");
    bad += fault_case(iso8583::HEADER_ASCII4, "    abc", iso8583::ERR_BAD_LENGTH, "spaces in the header");
    from_hex(raw, "1A34");
    bad += fault_case(iso8583::HEADER_BCD2, raw, iso8583::ERR_BAD_LENGTH, "nibble above nine");
    return bad;
}

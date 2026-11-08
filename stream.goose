// An incremental reader for framed messages. The caller feeds the bytes
// as they arrive from a stream. The reader holds at most one frame, and
// it checks the length in the header before it stores a body byte.
namespace iso8583;

import std;

// The width of the header in wire bytes.
fn header_width(header: i64) -> i64 {
    if header == HEADER_ASCII4 { return 4; }
    if header == HEADER_BCD2 || header == HEADER_BINARY2 { return 2; }
    return 0;
}

// Starts a reader for a header kind. HEADER_NONE has no length, so a
// stream of it cannot be split: it gives ERR_BAD_ARG.
fn reader_init(r: Reader&, header: i64) -> i64 {
    if header != HEADER_ASCII4 && header != HEADER_BCD2 && header != HEADER_BINARY2 { return ERR_BAD_ARG; }
    reader_reset(r);
    r.header = header;
    return OK;
}

// Clears the buffer and the fault. The header kind stays.
fn reader_reset(r: Reader&) {
    fill(r.buf, 0);
    r.buf.clear();
    r.state = STATE_HEADER;
    r.want = 0;
}

// True when a whole body waits.
fn reader_ready(r: Reader&) -> bool {
    return r.state == STATE_READY;
}

// Moves the body to out and makes the reader ready for the next frame.
// ERR_NOT_SET when no body waits. ERR_STREAM after a fault.
fn reader_take(r: Reader&, out: u8[>..]&) -> i64 {
    out.clear();
    if r.state == STATE_FAULT { return ERR_STREAM; }
    if r.state != STATE_READY { return ERR_NOT_SET; }
    out.append(r.buf);
    fill(r.buf, 0);
    r.buf.clear();
    r.state = STATE_HEADER;
    r.want = 0;
    return OK;
}

// Locks the reader after a fault. The buffer is cleared, so no bytes of a
// frame stay in it.
fn reader_fail(r: Reader&, code: i64) -> i64 {
    fill(r.buf, 0);
    r.buf.clear();
    r.state = STATE_FAULT;
    return code;
}

// Takes bytes from input up to the end of the current frame. Returns the
// count of bytes used and a fault code. After a fault the reader refuses
// input with ERR_STREAM until reader_reset. A reader that holds a whole
// body takes no bytes until reader_take.
fn reader_feed(r: Reader&, input: const u8[:]) -> i64, i64 {
    if r.state == STATE_FAULT { return 0, ERR_STREAM; }
    if r.state == STATE_READY { return 0, OK; }
    var used = 0;
    if r.state == STATE_HEADER {
        let w = header_width(r.header);
        if w == 0 { return 0, reader_fail(r, ERR_BAD_ARG); }
        let need = w - r.buf.len;
        var take = input.len;
        if take > need { take = need; }
        if take < 0 { take = 0; }
        r.buf.append(input[0..take]);
        used = take;
        if r.buf.len < w { return used, OK; }
        // The header is whole: read the length before any body byte.
        let n, f = frame_read_length(r.header, r.buf);
        if f != OK { return used, reader_fail(r, f); }
        fill(r.buf, 0);
        r.buf.clear();
        r.want = n;
        r.state = STATE_BODY;
    }
    if r.state == STATE_BODY {
        let need = r.want - r.buf.len;
        var take = input.len - used;
        if take > need { take = need; }
        if take < 0 { take = 0; }
        if r.buf.len + take > MAX_BUFFER { return used, reader_fail(r, ERR_TOO_LONG); }
        r.buf.append(input[used..used + take]);
        used += take;
        if r.buf.len == r.want { r.state = STATE_READY; }
    }
    return used, OK;
}

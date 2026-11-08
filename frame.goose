namespace iso8583;

import std;

// Largest body that each header can describe.
fn header_capacity(header: i64) -> i64 {
    if header == HEADER_ASCII4 || header == HEADER_BCD2 { return 9999; }
    return MAX_INPUT;
}

// Writes the header and then the body. out is empty on a fault.
fn frame_write(out: u8[>..]&, header: i64, body: const u8[:]) -> i64 {
    out.clear();
    if header < HEADER_NONE || header > HEADER_BINARY2 { return ERR_BAD_ARG; }
    if body.len > header_capacity(header) { return ERR_TOO_LONG; }
    if header != HEADER_NONE {
        let f = put_count(out, header_width_of(header), header_width(header), body.len, PAGE_500);
        if f != OK { out.clear(); return f; }
    }
    out.append(body);
    return OK;
}

// The count encoding of a header kind.
fn header_width_of(header: i64) -> i64 {
    if header == HEADER_ASCII4 { return ENC_ASCII; }
    if header == HEADER_BCD2 { return ENC_BCD; }
    return ENC_BINARY;
}

// Reads the length of the body from the first bytes of a stream. Returns
// the length and a fault code. The length is at most MAX_INPUT.
fn frame_read_length(header: i64, input: const u8[:]) -> i64, i64 {
    if header < HEADER_NONE || header > HEADER_BINARY2 { return 0, ERR_BAD_ARG; }
    if header == HEADER_NONE {
        if input.len > MAX_INPUT { return 0, ERR_TOO_LONG; }
        return input.len, OK;
    }
    let w = header_width(header);
    if input.len < w { return 0, ERR_TRUNCATED; }
    let n, f = get_count(input, 0, header_width_of(header), w, PAGE_500);
    if f != OK { return 0, f; }
    if n > header_capacity(header) || n > MAX_INPUT { return 0, ERR_TOO_LONG; }
    return n, OK;
}

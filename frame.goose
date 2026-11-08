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
    let n = body.len;
    if header == HEADER_ASCII4 {
        format_int(out, n, 10, 4, '0');
    } else if header == HEADER_BCD2 {
        out.push((((n / 1000) % 10) * 16 + (n / 100) % 10) as u8);
        out.push((((n / 10) % 10) * 16 + n % 10) as u8);
    } else if header == HEADER_BINARY2 {
        out.push((n / 256) as u8);
        out.push((n % 256) as u8);
    }
    out.append(body);
    return OK;
}

// Reads the length of the body from the first bytes of a stream. Returns
// the length and a fault code. The length is at most MAX_INPUT.
fn frame_read_length(header: i64, input: const u8[:]) -> i64, i64 {
    if header < HEADER_NONE || header > HEADER_BINARY2 { return 0, ERR_BAD_ARG; }
    if header == HEADER_NONE {
        if input.len > MAX_INPUT { return 0, ERR_TOO_LONG; }
        return input.len, OK;
    }
    if header == HEADER_ASCII4 {
        if input.len < 4 { return 0, ERR_TRUNCATED; }
        var n: i64 = 0;
        for i in 0..4 {
            if !is_digit(input[i]) { return 0, ERR_BAD_LENGTH; }
            n = n * 10 + (input[i] - '0');
        }
        return n, OK;
    }
    if input.len < 2 { return 0, ERR_TRUNCATED; }
    if header == HEADER_BCD2 {
        var n: i64 = 0;
        for i in 0..2 {
            let hi = (input[i] >> 4) as i64;
            let lo = (input[i] & 15) as i64;
            if hi > 9 || lo > 9 { return 0, ERR_BAD_LENGTH; }
            n = n * 100 + hi * 10 + lo;
        }
        return n, OK;
    }
    var n: i64 = input[0];
    n = n * 256 + input[1];
    if n > MAX_INPUT { return 0, ERR_TOO_LONG; }
    return n, OK;
}

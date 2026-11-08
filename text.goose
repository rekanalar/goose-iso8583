namespace iso8583;

import std;

fn is_digit(c: u8) -> bool {
    return c >= '0' && c <= '9';
}

// Value of an upper-case hex digit, or -1.
fn hex_value(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

fn hex_char(v: i64) -> u8 {
    let n = v % 16;
    if n < 10 { return '0' + (n as u8); }
    return 'A' + ((n - 10) as u8);
}

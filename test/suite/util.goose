namespace suite;

import std;

// Appends the bytes that the hex string h names to a fresh out buffer. Returns false on a bad digit.
fn from_hex(out: u8[>..]&, h: const u8[:]) -> bool {
    if h.len % 2 != 0 { return false; }
    var i = 0;
    while i < h.len {
        var hi: i64 = 0;
        var lo: i64 = 0;
        let a = h[i];
        let b = h[i + 1];
        if a >= '0' && a <= '9' { hi = a - '0'; } else if a >= 'A' && a <= 'F' { hi = a - 'A' + 10; } else { return false; }
        if b >= '0' && b <= '9' { lo = b - '0'; } else if b >= 'A' && b <= 'F' { lo = b - 'A' + 10; } else { return false; }
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    return true;
}

fn to_hex(out: u8[>..]&, v: const u8[:]) {
    out.clear();
    let digits = "0123456789ABCDEF";
    for i in 0..v.len {
        out.push(digits[v[i] >> 4]);
        out.push(digits[v[i] & 15]);
    }
}

fn same(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in 0..a.len {
        if a[i] != b[i] { return false; }
    }
    return true;
}

// Prints and counts a failed check. Returns 1 on failure, else 0.
fn check(ok: bool, what: const u8[:]) -> i64 {
    if !ok { print("FAIL: ", what, "\n"); return 1; }
    return 0;
}

// Compares two byte strings and shows both as hex on a failure.
fn eq_bytes(got: const u8[:], want: const u8[:], what: const u8[:]) -> i64 {
    if same(got, want) { return 0; }
    var g: u8[>..] = [];
    var w: u8[>..] = [];
    to_hex(g, got);
    to_hex(w, want);
    print("FAIL: ", what, "\n  got  ", g, "\n  want ", w, "\n");
    return 1;
}

// True when the text holds the part as a run of bytes.
fn has_run(text: const u8[:], part: const u8[:]) -> bool {
    if part.len == 0 { return true; }
    if part.len > text.len { return false; }
    for i in 0..(text.len - part.len + 1) {
        var ok = true;
        for j in 0..part.len {
            if text[i + j] != part[j] { ok = false; break; }
        }
        if ok { return true; }
    }
    return false;
}

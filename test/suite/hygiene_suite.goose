// The hygiene suite. It fails when a root .goose file of the package
// declares a namespace other than iso8583.
namespace suite;

import std;
import os;
import util;

// True when src holds a "namespace " line and every one of them is
// "namespace iso8583;".
fn ns_ok(src: const u8[:]) -> bool {
    let want = "namespace iso8583;";
    var found = false;
    var i = 0;
    while i < src.len {
        if (i == 0 || src[i - 1] == '\n') && i + 10 <= src.len {
            if same(src[i..i + 10], "namespace ") {
                var j = i;
                while j < src.len && src[j] != '\n' { j += 1; }
                if !same(src[i..j], want) { return false; }
                found = true;
            }
        }
        i += 1;
    }
    return found;
}

// The number of root files with a namespace other than iso8583.
fn bad_namespaces() -> i64 {
    var bad = 0;
    var names: u8[>..] = [];
    list_dir(".", names);
    var start = 0;
    while start < names.len {
        var end = start;
        while end < names.len && names[end] != '\n' { end += 1; }
        let name = names[start..end];
        if name.len > 6 && same(name[name.len - 6..name.len], ".goose") {
            var src: u8[>..] = [];
            read_file(name, src);
            if !ns_ok(src) { bad += 1; }
        }
        start = end + 1;
    }
    return bad;
}

// The check finds a root file that declares another namespace. The
// planted file is removed again before the check returns.
fn run_hygiene_plant() -> i64 {
    var bad = 0;
    let planted = "planted_namespace_check.goose";
    if bad_namespaces() != 0 { return check(false, "the root files are clean before the plant"); }
    var src: u8[>..] = [];
    src.append("namespace goose_iso8583;\n");
    if !write_file(planted, src) { return check(false, "the planted file is written"); }
    let found = bad_namespaces();
    delete_file(planted);
    if file_exists(planted) { bad += check(false, "the planted file is removed"); }
    bad += check(found == 1, "the check finds the planted file");
    bad += check(bad_namespaces() == 0, "the root files are clean after the plant");
    return bad;
}

fn run_hygiene() -> i64 {
    var bad = 0;
    let n = bad_namespaces();
    if n > 0 {
        print("FAIL: ", n, " root files hold another namespace\n");
        bad += n;
    }
    bad += run_hygiene_plant();
    return bad;
}

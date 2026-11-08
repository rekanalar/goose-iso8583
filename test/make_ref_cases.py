#!/usr/bin/env python3
"""Generate test/suite/ref_cases.goose and test/suite/ref_dialects.goose.

The wire bytes come from the encoder of the Python package iso8583
(pyiso8583), run on seeded random messages. The Goose tests unpack those
bytes, compare every field, and pack the message again. The Python decoder
must read each message back to the same values, or the script stops.

Four dialects are covered: the default ASCII dialect, an EBCDIC dialect
with binary bitmaps and a tertiary bitmap, a BCD dialect with odd digit
counts and both pad sides, and a dialect with ASCII bitmaps and binary
length prefixes.

Run (the argument is the root of a pyiso8583 checkout):
  python3 test/make_ref_cases.py path/to/pyiso8583
"""
import copy
import os
import random
import sys

TEXT = "text"
DIGITS = "digits"
BINARY = "binary"

# Constants of the package.
ASCII, EBCDIC, BCD, BINARY_ENC, HEX = 0, 1, 2, 3, 4
FIXED, LLVAR, LLLVAR = 0, 1, 2
BYTES, NIBBLES = 0, 1
LEFT, RIGHT = 0, 1


def f(py, kind, enc, prefix, unit, max_len, pad, vk):
    return dict(py=py, ours=(kind, enc, prefix, unit, max_len, pad), vk=vk)


def py_spec(data_enc, len_enc, len_type, max_len, **extra):
    d = dict(data_enc=data_enc, len_enc=len_enc, len_type=len_type, max_len=max_len, desc="x")
    d.update(extra)
    return d


DIALECTS = {
    # name: (mti_enc, bitmap_enc, bitmaps, py header, fields)
    "ebcdic": dict(
        mti=EBCDIC, bitmap=0, bitmaps=3,
        head=dict(t=py_spec("cp500", "ascii", 0, 4), p=py_spec("b", "ascii", 0, 8), b1=py_spec("b", "ascii", 0, 8)),
        fields={
            2: f(py_spec("cp500", "cp500", 2, 19), LLVAR, EBCDIC, EBCDIC, BYTES, 19, LEFT, DIGITS),
            3: f(py_spec("cp500", "ascii", 0, 6), FIXED, EBCDIC, 0, BYTES, 6, LEFT, DIGITS),
            4: f(py_spec("b", "ascii", 0, 6), FIXED, BINARY_ENC, 0, BYTES, 6, LEFT, BINARY),
            11: f(py_spec("cp500", "ascii", 0, 6), FIXED, EBCDIC, 0, BYTES, 6, LEFT, DIGITS),
            35: f(py_spec("b", "bcd", 1, 37), LLVAR, BINARY_ENC, BCD, BYTES, 37, LEFT, BINARY),
            48: f(py_spec("cp500", "b", 2, 300), LLLVAR, EBCDIC, BINARY_ENC, BYTES, 300, LEFT, TEXT),
            64: f(py_spec("b", "ascii", 0, 8), FIXED, BINARY_ENC, 0, BYTES, 8, LEFT, BINARY),
            70: f(py_spec("cp500", "ascii", 0, 3), FIXED, EBCDIC, 0, BYTES, 3, LEFT, DIGITS),
            102: f(py_spec("cp500", "cp500", 2, 28), LLVAR, EBCDIC, EBCDIC, BYTES, 28, LEFT, TEXT),
            130: f(py_spec("cp500", "ascii", 0, 4), FIXED, EBCDIC, 0, BYTES, 4, LEFT, TEXT),
            150: f(py_spec("cp500", "cp500", 2, 20), LLVAR, EBCDIC, EBCDIC, BYTES, 20, LEFT, TEXT),
        }),
    "bcd": dict(
        mti=BCD, bitmap=0, bitmaps=2,
        head=dict(t=py_spec("b", "ascii", 0, 2), p=py_spec("b", "ascii", 0, 8), b1=py_spec("b", "ascii", 0, 8)),
        fields={
            2: f(py_spec("b", "bcd", 1, 19, len_count="nibbles", left_pad="0"), LLVAR, BCD, BCD, NIBBLES, 19, LEFT, DIGITS),
            3: f(py_spec("b", "ascii", 0, 3), FIXED, BCD, 0, BYTES, 3, LEFT, DIGITS),
            4: f(py_spec("b", "ascii", 0, 6), FIXED, BCD, 0, BYTES, 6, LEFT, DIGITS),
            12: f(py_spec("b", "ascii", 0, 5, len_count="nibbles", left_pad="0"), FIXED, BCD, 0, NIBBLES, 5, LEFT, DIGITS),
            22: f(py_spec("b", "ascii", 0, 3, len_count="nibbles", right_pad="0"), FIXED, BCD, 0, NIBBLES, 3, RIGHT, DIGITS),
            35: f(py_spec("b", "bcd", 1, 37, len_count="nibbles", right_pad="0"), LLVAR, BCD, BCD, NIBBLES, 37, RIGHT, DIGITS),
            55: f(py_spec("b", "bcd", 2, 255), LLLVAR, BINARY_ENC, BCD, BYTES, 255, LEFT, BINARY),
            90: f(py_spec("b", "ascii", 0, 21), FIXED, BCD, 0, BYTES, 21, LEFT, DIGITS),
            128: f(py_spec("b", "ascii", 0, 8), FIXED, BINARY_ENC, 0, BYTES, 8, LEFT, BINARY),
        }),
    "binlen": dict(
        mti=ASCII, bitmap=1, bitmaps=2,
        head=dict(t=py_spec("ascii", "ascii", 0, 4), p=py_spec("ascii", "ascii", 0, 16), b1=py_spec("ascii", "ascii", 0, 16)),
        fields={
            2: f(py_spec("ascii", "b", 1, 19), LLVAR, ASCII, BINARY_ENC, BYTES, 19, LEFT, DIGITS),
            3: f(py_spec("ascii", "ascii", 0, 6), FIXED, ASCII, 0, BYTES, 6, LEFT, DIGITS),
            41: f(py_spec("ascii", "ascii", 0, 8), FIXED, ASCII, 0, BYTES, 8, LEFT, TEXT),
            48: f(py_spec("ascii", "b", 2, 600), LLLVAR, ASCII, BINARY_ENC, BYTES, 600, LEFT, TEXT),
            62: f(py_spec("ascii", "ascii", 3, 120), LLLVAR, ASCII, ASCII, BYTES, 120, LEFT, TEXT),
            100: f(py_spec("ascii", "ascii", 2, 11), LLVAR, ASCII, ASCII, BYTES, 11, LEFT, DIGITS),
        }),
}


def rand_value(rng, vk, ours):
    kind, enc, prefix, unit, max_len, pad = ours
    if enc in (BCD, HEX) and unit == BYTES:
        cap = max_len * 2
    else:
        cap = max_len
    n = cap
    if kind != FIXED:
        # Long values stay rare, so the generated file stays small.
        n = cap if (cap <= 40 and rng.random() < 0.15) else rng.randint(1, min(cap, 40))
    if enc in (BCD, HEX) and unit == BYTES and kind != FIXED:
        n = max(2, n - n % 2)
    if vk == DIGITS:
        return "".join(rng.choice("0123456789") for _ in range(n))
    if vk == BINARY:
        return bytes(rng.randrange(256) for _ in range(n))
    return "".join(chr(rng.randint(32, 126)) for _ in range(n))


def py_value(vk, v):
    return v.hex().upper() if vk == BINARY else v


def our_hex(vk, v):
    return (v if vk == BINARY else v.encode("ascii")).hex().upper()


def goose_str(s):
    return '"%s"' % s


def main(root):
    sys.path.insert(0, root)
    import iso8583
    from iso8583.specs import default_ascii

    rng = random.Random(8583)
    cases = []  # (dialect index, wire hex, mti, [(id, hex)])
    mtis = ["0100", "0110", "0200", "0210", "0420", "0800"]
    names = ["default"] + list(DIALECTS)

    def emit(di, spec, fields_meta):
        for n in range(14):
            ids = sorted(fields_meta)
            k = rng.randint(0, len(ids)) if n > 1 else (0 if n == 0 else len(ids))
            chosen = sorted(rng.sample(ids, k))
            if n == 2 and chosen:
                chosen = chosen[:1]
            doc = {"t": rng.choice(mtis)}
            vals = []
            for i in chosen:
                m = fields_meta[i]
                v = rand_value(rng, m["vk"], m["ours"])
                doc[str(i)] = py_value(m["vk"], v)
                vals.append((i, our_hex(m["vk"], v)))
            raw, _ = iso8583.encode(doc, spec)
            back, _ = iso8583.decode(bytes(raw), spec)
            for key in doc:
                if back[key] != doc[key]:
                    sys.exit("reference decoder disagrees on %s %s" % (names[di], key))
            cases.append((di, bytes(raw).hex().upper(), doc["t"], vals))

    # default ASCII dialect
    meta = {}
    for i in range(2, 129):
        if i == 65:
            continue
        s = default_ascii[str(i)]
        kind = {0: FIXED, 2: LLVAR, 3: LLLVAR}[s["len_type"]]
        meta[i] = dict(vk=TEXT, ours=(kind, ASCII, ASCII, BYTES, s["max_len"], LEFT))
    emit(0, copy.deepcopy(default_ascii), meta)

    table = []
    for i in range(2, 129):
        if i != 65:
            table.append((i, meta[i]["ours"][0], meta[i]["ours"][4]))

    dlines = []
    for di, name in enumerate(DIALECTS, start=1):
        d = DIALECTS[name]
        spec = copy.deepcopy(default_ascii)
        spec["t"] = d["head"]["t"]
        spec["p"] = d["head"]["p"]
        spec["1"] = d["head"]["b1"]
        for i, m in d["fields"].items():
            spec[str(i)] = m["py"]
        emit(di, spec, d["fields"])
        dlines.append("    if which == %d {" % di)
        dlines.append("        iso8583::dialect_init(d, %d, %d, %d);" % (d["mti"], d["bitmap"], d["bitmaps"]))
        for i, m in sorted(d["fields"].items()):
            o = m["ours"]
            dlines.append("        iso8583::dialect_field(d, %d, %d, %d, %d, %d, %d, %d, 0);" % (
                i, o[0], o[1], o[2], o[3], o[4], o[5]))
        dlines.append("    }")

    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "suite")
    with open(os.path.join(out, "ref_cases.goose"), "w") as fh:
        fh.write("// Generated by test/make_ref_cases.py. Do not edit by hand.\n")
        fh.write("// Messages that the encoder of pyiso8583 wrote, as hex.\n")
        fh.write("namespace suite;\n\n")
        n = len(cases)
        fh.write("const REF_COUNT: i64 = %d;\n" % n)
        fh.write("// Dialect of each case: 0 default, 1 ebcdic, 2 bcd, 3 binlen.\n")
        fh.write("const REF_DIALECT: i64[%d] = [%s];\n" % (n, ", ".join(str(c[0]) for c in cases)))
        fh.write("const REF_WIRE: const u8[:][%d] = [\n" % n)
        for c in cases:
            fh.write("    %s,\n" % goose_str(c[1]))
        fh.write("];\n")
        fh.write("// The MTI, then each field as id=hex of the value, separated by commas.\n")
        fh.write("const REF_FIELDS: const u8[:][%d] = [\n" % n)
        for c in cases:
            fh.write("    %s,\n" % goose_str(c[2] + ";" + ",".join("%d=%s" % (i, h) for i, h in c[3])))
        fh.write("];\n")
    with open(os.path.join(out, "default_table.goose"), "w") as fh:
        fh.write("// Generated by test/make_ref_cases.py. Do not edit by hand.\n")
        fh.write("// Kind and max_len of fields 2 to 128 (not 65) in the default_ascii table of pyiso8583.\n")
        fh.write("namespace suite;\n\n")
        fh.write("const DEFAULT_TABLE: i64[%d] = [\n" % (len(table) * 3))
        for r in table:
            fh.write("    %d, %d, %d,\n" % r)
        fh.write("];\n")
    with open(os.path.join(out, "ref_dialects.goose"), "w") as fh:
        fh.write("// Generated by test/make_ref_cases.py. Do not edit by hand.\n")
        fh.write("namespace suite;\n\nimport iso8583 from \"../..\";\n\n")
        fh.write("// Builds dialect 1 (ebcdic), 2 (bcd) or 3 (binlen). 0 is the default dialect.\n")
        fh.write("fn ref_dialect(d: iso8583::Dialect&, which: i64) {\n")
        fh.write("    if which == 0 { iso8583::dialect_default_ascii(d); }\n")
        fh.write("\n".join(dlines) + "\n}\n")
    print("cases:", len(cases))


if len(sys.argv) != 2:
    sys.exit(__doc__)
main(sys.argv[1])

#!/usr/bin/env python3
"""Generate default_dialect93.goose: the ISO 8583:1993 default dialects.

The tables come from ISO93APackager.java and ISO93BPackager.java of the
jPOS project (AGPL-3.0), read as text. The script never runs code from
the reference. The output holds numbers only: the field id, the kind,
the encodings, the unit, the maximum length, the pad side, the pad
digit, the pad character and the mask mode. No name, title or comment of
the reference enters the file, and a test of the suite checks that.

The reference declares the same field shapes in both variants. The
variants differ in the encodings: the A variant is plain ASCII, the B
variant uses BCD digits and binary bytes. The amount field of the
standard is ASCII text of 17 characters in the A variant and a binary
field of 9 bytes (a sign byte and 8 bytes of BCD digits) in the B
variant.

The script also writes test/suite/ref93_cases.goose: one sample message
per variant, packed by the helper below under the same rules, for the
tests of the package.

Run:
  python3 test/make_default93.py path/to/jpos/jpos
"""
import re
import sys

# Mask modes of the package, as in the default 1987 dialect: PAN for the
# account numbers and names, full for the track and security fields.
PAN = {2, 34, 102, 103}
# Fields 48 and 120 to 127 hold private network data of unknown shape.
# They stay fully masked in the text form.
FULL = {35, 36, 45, 48, 52, 53, 55, 120, 121, 122, 123, 124, 125, 126, 127}

# Kind constants of the package.
FIXED, LLVAR, LLLVAR = 0, 1, 2
ENC_ASCII, ENC_EBCDIC, ENC_BCD, ENC_BINARY, ENC_HEX = 0, 1, 2, 3, 4
UNIT_BYTES, UNIT_NIBBLES = 0, 1
PAD_LEFT, PAD_RIGHT = 0, 1

ROW = {
    # A variant: plain ASCII. The zero-padded numeric fields take their
    # full length, so they carry no pad character: a pad character would
    # strip the leading zeros of the value on decode.
    "IFA_NUMERIC":    (FIXED, ENC_ASCII, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFA_LLNUM":      (LLVAR, ENC_ASCII, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFA_LLCHAR":     (LLVAR, ENC_ASCII, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFA_LLLCHAR":    (LLLVAR, ENC_ASCII, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IF_CHAR":        (FIXED, ENC_ASCII, ENC_ASCII, UNIT_BYTES, "n", PAD_RIGHT, 0, 32),
    "IFA_BINARY":     (FIXED, ENC_HEX, ENC_ASCII, UNIT_NIBBLES, "2n", PAD_LEFT, 0, -1),
    "IFA_LLBINARY":   (LLVAR, ENC_BINARY, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFA_LLLBINARY":  (LLLVAR, ENC_BINARY, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFA_AMOUNT":     (FIXED, ENC_ASCII, ENC_ASCII, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    # B variant: BCD digits and binary bytes.
    "IFB_NUMERIC":    (FIXED, ENC_BCD, ENC_BCD, UNIT_NIBBLES, "n", PAD_RIGHT, 0, -1),
    "IFB_LLNUM":      (LLVAR, ENC_BCD, ENC_BCD, UNIT_NIBBLES, "n", PAD_RIGHT, 0, -1),
    "IFB_LLCHAR":     (LLVAR, ENC_ASCII, ENC_BCD, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFB_LLLCHAR":    (LLLVAR, ENC_ASCII, ENC_BCD, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFB_BINARY":     (FIXED, ENC_BINARY, ENC_BCD, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFB_LLBINARY":   (LLVAR, ENC_BINARY, ENC_BCD, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    "IFB_LLLBINARY":  (LLLVAR, ENC_BINARY, ENC_BCD, UNIT_BYTES, "n", PAD_LEFT, 0, -1),
    # The B amount: a sign byte and half of the declared digits in BCD.
    "IFB_AMOUNT":     (FIXED, ENC_BINARY, ENC_BCD, UNIT_BYTES, "1+n/2", PAD_LEFT, 0, -1),
}

PAT = re.compile(r'/\*(\d+)\*/\s*new\s+([A-Z_]+)\s*\(\s*([0-9+ ]+?)\s*,\s*"[^"]*"\s*(,\s*pad)?\s*\)')


def parse(path):
    fields = {}
    pad_flag = "pad = true" in open(path).read()
    for line in open(path):
        m = PAT.search(line)
        if not m:
            continue
        fid = int(m.group(1))
        # The regex holds only digits, spaces and a plus, so the length
        # is a small sum. No interpreter runs here.
        ln = m.group(3).strip()
        if "+" in ln:
            parts = ln.split("+")
            n = sum(int(p) for p in parts)
        else:
            n = int(ln)
        fields[fid] = (m.group(2), n)
    return fields, pad_flag


def max_len(rule, n):
    expr = rule[4]
    if expr == "n":
        return n
    if expr == "2n":
        return 2 * n
    if expr == "1+n/2":
        return 1 + n // 2
    sys.exit("unknown length rule " + expr)


def rows_of(fields):
    out = []
    for fid in sorted(fields):
        if fid in (0, 1, 65):
            # MTI, bitmap and the tertiary bitmap indicator are package-owned.
            continue
        cls, n = fields[fid]
        rule = ROW[cls]
        mask = 1 if fid in PAN else 2 if fid in FULL else 0
        out.append((fid, rule[0], rule[1], rule[2], rule[3],
                    max_len(rule, n), rule[5], rule[6], rule[7], mask))
    return out


def sample(rows, variant):
    """Packs one message per the table: fields 2, 3, 4, 7, 11, 12, 24, 39."""
    spec = {r[0]: r for r in rows}
    values = {2: "4000000000000000019", 3: "000000", 4: "000000000100",
              7: "0708103015", 11: "000123", 12: "202607081030",
              24: "000", 39: "000"}
    present = sorted(values)
    bits = [1 << (64 - i) for i in present]
    bitmap = sum(bits)
    wire = bytearray()
    if variant == "a":
        wire += b"0800"
        wire += ("%016X" % bitmap).encode()
    else:
        wire += bytes.fromhex("0800")
        wire += bitmap.to_bytes(8, "big")
    for fid in present:
        r = spec[fid]
        _, kind, enc, penc, unit, n, padding, pad_digit, pad_char, mask = r
        v = values[fid]
        assert len(v) == n, (fid, len(v), n)
        if kind == LLVAR or kind == LLLVAR:
            w = 2 if kind == LLVAR else 3
            if variant == "a":
                wire += ("%0*d" % (w, len(v))).encode()
            else:
                # A BCD prefix packs two digits per byte, left-padded
                # with a zero digit to a whole byte count.
                wire += bytes.fromhex("%0*d" % (w + w % 2, len(v)))
        if enc == ENC_ASCII:
            wire += v.encode()
        elif enc == ENC_BCD:
            if len(v) % 2 == 1:
                v = v + "0"  # The right pad nibble of an odd digit count.
            wire += bytes.fromhex(v)
        elif enc == ENC_BINARY:
            wire += bytes.fromhex(v)
        elif enc == ENC_HEX:
            wire += bytes.fromhex(v)
    return bytes(wire).hex().upper()


def main(root):
    a_fields, _ = parse(root + "/src/main/java/org/jpos/iso/packager/ISO93APackager.java")
    b_fields, _ = parse(root + "/src/main/java/org/jpos/iso/packager/ISO93BPackager.java")
    if len(a_fields) != 129 or len(b_fields) != 129:
        sys.exit("expected 129 entries in each table")
    a_rows = rows_of(a_fields)
    b_rows = rows_of(b_fields)
    if len(a_rows) != len(b_rows) or len(a_rows) != 126:
        sys.exit("expected 126 data fields")
    for ra, rb in zip(a_rows, b_rows):
        if ra[0] != rb[0] or ra[1] != rb[1]:
            sys.exit("the variants disagree on field %d" % ra[0])
        # The variants hold the same field in different encodings: the
        # size must agree in bytes on the wire. The amount field is the
        # one exception: the B variant holds the digits in BCD, so its
        # wire form is about half of the ASCII one.
        if fid97 := (ra[0] == 97):
            continue
        if ra[4] == UNIT_NIBBLES and rb[4] == UNIT_BYTES:
            if ra[5] / 2 != rb[5]:
                sys.exit("the variants disagree on the size of field %d" % ra[0])
        elif ra[5] != rb[5]:
            sys.exit("the variants disagree on the size of field %d" % ra[0])

    hdr = ["// Generated by test/make_default93.py. Do not edit by hand.",
           "// The ISO 8583:1993 field tables, in an ASCII and a BCD variant.",
           "// The tables come from the ISO93A and ISO93B packager sources of",
           "// the jPOS project, read as text. The output holds numbers only:",
           "// one row of 15 numbers per field: the id, kind, max length, pad",
           "// side and mask, then the encoding, prefix encoding, unit, pad",
           "// digit and pad character of the ASCII variant, then those five",
           "// of the BCD variant.",
           "namespace iso8583;", "", "import std;", ""]

    def emit(name, rows, mti_enc, bitmap_enc):
        hdr.append("fn %s(d: Dialect&) {" % name)
        hdr.append("    dialect_init(d, ENC_%s, BITMAP_%s, 2);" %
                   ("ASCII" if mti_enc == ENC_ASCII else "BCD",
                    "HEX_ASCII" if bitmap_enc == ENC_ASCII else "BINARY"))
        hdr.append("    for r in 0..%d {" % len(rows))
        hdr.append("        let b = r * 10;")
        hdr.append("        dialect_field(d, TABLE_93[b], TABLE_93[b + 1], ENC_ASCII, ENC_ASCII,")
        hdr.append("                      UNIT_BYTES, 999, PAD_LEFT, TABLE_93[b + 9]);")
        hdr.append("    }")
        hdr.append("}")

    # One flat table of 10 numbers per field, shared by both variants:
    # id, kind, max_len, pad side, pad digit, pad char, mask, then the
    # encodings of the A and the B variant.
    flat = []
    for ra, rb in zip(a_rows, b_rows):
        fid, kind, _, _, _, n, padding, pad_digit, pad_char, mask = ra
        # A: enc, prefix_enc, unit. B: enc, prefix_enc, unit.
        ae, ape, au = ra[2], ra[3], ra[4]
        be, bpe, bu = rb[2], rb[3], rb[4]
        pad_a = ra[7]
        pad_b = rb[7]
        pc_a = ra[8]
        pc_b = rb[8]
        side_a = ra[6]
        side_b = rb[6]
        flat.extend([fid, kind, n, mask, ae, ape, au, side_a, pad_a, pc_a,
                     be, bpe, bu, side_b, pad_b, pc_b])
    lines = list(hdr)
    lines.append("const T93: i64[%d] = [" % (len(flat)))
    for i in range(0, len(flat), 5):
        lines.append("    " + ", ".join(str(x) for x in flat[i:i + 5]) + ",")
    lines.append("];")
    lines.append("")
    lines.append("fn dialect_default_1993_ascii(d: Dialect&) {")
    lines.append("    dialect_init(d, ENC_ASCII, BITMAP_HEX_ASCII, 2);")
    lines.append("    for r in 0..%d {" % len(a_rows))
    lines.append("        let b = r * 16;")
    lines.append("        dialect_field(d, T93[b], T93[b + 1], T93[b + 4], T93[b + 5],")
    lines.append("                      T93[b + 6], T93[b + 2], T93[b + 7], T93[b + 3]);")
    lines.append("        if T93[b + 8] != 0 || T93[b + 9] != -1 {")
    lines.append("            dialect_field_pad(d, path1(T93[b]), T93[b + 8], T93[b + 9]);")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("fn dialect_default_1993_binary(d: Dialect&) {")
    lines.append("    dialect_init(d, ENC_BCD, BITMAP_BINARY, 2);")
    lines.append("    for r in 0..%d {" % len(b_rows))
    lines.append("        let b = r * 16;")
    lines.append("        dialect_field(d, T93[b], T93[b + 1], T93[b + 10], T93[b + 11],")
    lines.append("                      T93[b + 12], T93[b + 2], T93[b + 13], T93[b + 3]);")
    lines.append("        if T93[b + 14] != 0 || T93[b + 15] != -1 {")
    lines.append("            dialect_field_pad(d, path1(T93[b]), T93[b + 14], T93[b + 15]);")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    with open("default_dialect93.goose", "w") as f:
        f.write("\n".join(lines) + "\n")

    cases = ["// Generated by test/make_default93.py. Do not edit by hand.",
             "namespace suite;", "",
             "// The wire form of one sample message per variant: the fields",
             "// 2, 3, 4, 7, 11, 12, 24 and 39, packed under the same table.",
             "// The values are 4000000000000000019, 000000, 000000000100,",
             "// 0708103015, 000123, 202607081030, 000 and 000.",
             'const SAMPLE93_A: const u8[:] = "%s";' % sample(a_rows, "a"),
             'const SAMPLE93_B: const u8[:] = "%s";' % sample(b_rows, "b"),
             'const SAMPLE93_FIELDS: const u8[:] = "4000000000000000019,000000,000000000100,0708103015,000123,202607081030,000,000";']
    with open("test/suite/ref93_cases.goose", "w") as f:
        f.write("\n".join(cases) + "\n")
    print("default_dialect93.goose and test/suite/ref93_cases.goose written")
    print("field 39 length: 1993 = %d" % a_rows[[r[0] for r in a_rows].index(39)][5])


if len(sys.argv) != 2:
    sys.exit(__doc__)
main(sys.argv[1])

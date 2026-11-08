namespace suite;

import std;
import iso8583 from "../..";
import default_table;
import util;

// True when two dialects hold the same field table.
fn same_dialect(a: iso8583::Dialect&, b: iso8583::Dialect&) -> bool {
    if a.mti_enc != b.mti_enc || a.bitmap_enc != b.bitmap_enc || a.bitmaps != b.bitmaps { return false; }
    for i in 0..193 {
        let x = a.fields[i];
        let y = b.fields[i];
        if x.defined != y.defined || x.kind != y.kind || x.enc != y.enc || x.prefix_enc != y.prefix_enc { return false; }
        if x.unit != y.unit || x.max_len != y.max_len || x.padding != y.padding || x.mask != y.mask { return false; }
    }
    return true;
}

fn run_dialect() -> i64 {
    var bad = 0;
    var d = iso8583::Dialect { .. };
    bad += check(iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_BINARY, 2) == iso8583::OK, "init");
    let A = iso8583::ENC_ASCII;
    let U = iso8583::UNIT_BYTES;
    let L = iso8583::PAD_LEFT;
    let FX = iso8583::KIND_FIXED;
    let V2 = iso8583::KIND_LLVAR;
    let V3 = iso8583::KIND_LLLVAR;
    bad += check(iso8583::dialect_field(d, 3, FX, A, 0, U, 6, L, 0) == iso8583::OK, "define field 3");
    var before = d;
    // Every bad argument gives a fault code and leaves the dialect as it was.
    bad += check(iso8583::dialect_field(d, 129, FX, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_FIELD_ID, "id 129 in a two-bitmap dialect");
    bad += check(iso8583::dialect_field(d, 1, FX, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_FIELD_ID, "id 1");
    bad += check(iso8583::dialect_field(d, 65, FX, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_FIELD_ID, "id 65");
    bad += check(iso8583::dialect_field(d, 0, FX, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_FIELD_ID, "id 0");
    bad += check(iso8583::dialect_field(d, -4, FX, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_FIELD_ID, "negative id");
    bad += check(iso8583::dialect_field(d, 193, FX, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_FIELD_ID, "id 193");
    bad += check(iso8583::dialect_field(d, 4, 3, A, 0, U, 6, L, 0) == iso8583::ERR_BAD_ARG, "kind 3");
    bad += check(iso8583::dialect_field(d, 4, FX, 9, 0, U, 6, L, 0) == iso8583::ERR_BAD_ARG, "encoding 9");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, 2, 6, L, 0) == iso8583::ERR_BAD_ARG, "unit 2");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, U, 6, 2, 0) == iso8583::ERR_BAD_ARG, "padding 2");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, U, 6, L, 3) == iso8583::ERR_BAD_ARG, "mask 3");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, U, 0, L, 0) == iso8583::ERR_BAD_ARG, "max_len 0");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, U, -1, L, 0) == iso8583::ERR_BAD_ARG, "max_len negative");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, U, 1000, L, 0) == iso8583::ERR_BAD_ARG, "max_len 1000");
    bad += check(iso8583::dialect_field(d, 4, V2, A, A, U, 100, L, 0) == iso8583::ERR_BAD_ARG, "LLVAR max_len 100");
    bad += check(iso8583::dialect_field(d, 4, V2, A, iso8583::ENC_BINARY, U, 256, L, 0) == iso8583::ERR_BAD_ARG, "LLVAR binary prefix max_len 256");
    bad += check(iso8583::dialect_field(d, 4, V3, A, A, U, 1000, L, 0) == iso8583::ERR_BAD_ARG, "LLLVAR max_len 1000");
    bad += check(iso8583::dialect_field(d, 4, V2, A, iso8583::ENC_HEX, U, 10, L, 0) == iso8583::ERR_BAD_ARG, "prefix encoding hex");
    bad += check(iso8583::dialect_field(d, 4, FX, A, 0, iso8583::UNIT_NIBBLES, 6, L, 0) == iso8583::ERR_BAD_ARG, "nibbles on ASCII");
    bad += check(iso8583::dialect_field(d, 4, FX, iso8583::ENC_BINARY, 0, iso8583::UNIT_NIBBLES, 6, L, 0) == iso8583::ERR_BAD_ARG, "nibbles on binary");
    bad += check(same_dialect(d, before), "a bad call leaves the dialect unchanged");
    bad += check(iso8583::dialect_init(d, 7, iso8583::BITMAP_BINARY, 2) == iso8583::ERR_BAD_ARG, "init MTI encoding 7");
    bad += check(iso8583::dialect_init(d, A, 5, 2) == iso8583::ERR_BAD_ARG, "init bitmap encoding 5");
    bad += check(iso8583::dialect_init(d, A, iso8583::BITMAP_BINARY, 4) == iso8583::ERR_BAD_ARG, "init bitmaps 4");
    bad += check(same_dialect(d, before), "a bad init leaves the dialect unchanged");
    // A three-bitmap dialect takes ids up to 192.
    var t = iso8583::Dialect { .. };
    iso8583::dialect_init(t, A, iso8583::BITMAP_BINARY, 3);
    bad += check(iso8583::dialect_field(t, 192, FX, A, 0, U, 6, L, 0) == iso8583::OK, "id 192 with three bitmaps");
    bad += check(iso8583::dialect_has(t, 192) && !iso8583::dialect_has(t, 191), "dialect_has");

    // A copy is independent of the original.
    var e = before;
    iso8583::dialect_field(e, 5, FX, A, 0, U, 9, L, 0);
    bad += check(iso8583::dialect_has(e, 5) && !iso8583::dialect_has(before, 5), "a copy does not change the original");

    // The default dialect holds the table of pyiso8583.
    var def = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(def);
    bad += check(def.bitmaps == 2 && def.mti_enc == iso8583::ENC_ASCII && def.bitmap_enc == iso8583::BITMAP_HEX_ASCII, "default framing");
    var seen = 0;
    for r in 0..(DEFAULT_TABLE.len / 3) {
        let id = DEFAULT_TABLE[r * 3];
        let f = def.fields[id];
        if !f.defined || f.kind != DEFAULT_TABLE[r * 3 + 1] || f.max_len != DEFAULT_TABLE[r * 3 + 2] || f.enc != iso8583::ENC_ASCII {
            print("FAIL: default field ", id, "\n");
            bad += 1;
        }
        seen += 1;
    }
    bad += check(seen == 126, "126 default fields");
    bad += check(!iso8583::dialect_has(def, 1) && !iso8583::dialect_has(def, 65) && !iso8583::dialect_has(def, 129), "no default field 1, 65, 129");
    bad += check(def.fields[2].mask == iso8583::MASK_PAN && def.fields[35].mask == iso8583::MASK_FULL && def.fields[52].mask == iso8583::MASK_FULL, "default masks");
    bad += check(def.fields[55].mask == iso8583::MASK_FULL && def.fields[102].mask == iso8583::MASK_PAN && def.fields[41].mask == iso8583::MASK_NONE, "default masks 2");
    // A copy of the default with one override.
    var mine = def;
    iso8583::dialect_field(mine, 3, iso8583::KIND_FIXED, iso8583::ENC_ASCII, 0, U, 4, L, 0);
    bad += check(mine.fields[3].max_len == 4 && def.fields[3].max_len == 6, "override on a copy");
    return bad;
}

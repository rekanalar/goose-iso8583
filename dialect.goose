namespace iso8583;

import std;

// Clears d and sets its framing. mti_enc is ENC_ASCII, ENC_EBCDIC or
// ENC_BCD. bitmap_enc is a BITMAP_* value. bitmaps is 2, or 3 for a
// dialect with a tertiary bitmap and the fields 129 to 192. d stays
// unchanged when an argument is bad.
fn dialect_init(d: Dialect&, mti_enc: i64, bitmap_enc: i64, bitmaps: i64) -> i64 {
    if mti_enc != ENC_ASCII && mti_enc != ENC_EBCDIC && mti_enc != ENC_BCD { return ERR_BAD_ARG; }
    if bitmap_enc < BITMAP_BINARY || bitmap_enc > BITMAP_HEX_EBCDIC { return ERR_BAD_ARG; }
    if bitmaps != 2 && bitmaps != 3 { return ERR_BAD_ARG; }
    d.mti_enc = mti_enc;
    d.bitmap_enc = bitmap_enc;
    d.bitmaps = bitmaps;
    d.page = PAGE_500;
    for i in 0..193 { d.fields[i] = FieldSpec { .. }; }
    for i in 0..192 { d.subs[i] = FieldSpec { .. }; }
    return OK;
}

// Defines the field id. Field 1 and field 65 belong to the package. The
// call checks every argument and leaves d unchanged on a fault.
fn dialect_field(d: Dialect&, id: i64, kind: i64, enc: i64, prefix_enc: i64, unit: i64, max_len: i64, padding: i64, mask: i64) -> i64 {
    if !valid_id(id) { return ERR_BAD_FIELD_ID; }
    if id > 128 && d.bitmaps < 3 { return ERR_BAD_FIELD_ID; }
    if kind < KIND_FIXED || kind > KIND_LLLVAR { return ERR_BAD_ARG; }
    if enc < ENC_ASCII || enc > ENC_HEX { return ERR_BAD_ARG; }
    if unit != UNIT_BYTES && unit != UNIT_NIBBLES { return ERR_BAD_ARG; }
    if padding != PAD_LEFT && padding != PAD_RIGHT { return ERR_BAD_ARG; }
    if mask < MASK_NONE || mask > MASK_FULL { return ERR_BAD_ARG; }
    if kind != KIND_FIXED {
        if prefix_enc != ENC_ASCII && prefix_enc != ENC_EBCDIC && prefix_enc != ENC_BCD && prefix_enc != ENC_BINARY { return ERR_BAD_ARG; }
    }
    if unit == UNIT_NIBBLES && !is_nibble_enc(enc) { return ERR_BAD_ARG; }
    if max_len < 1 || max_len > prefix_cap(prefix_enc, kind) { return ERR_BAD_ARG; }
    d.fields[id] = FieldSpec {
        defined: true, kind: kind, enc: enc, prefix_enc: prefix_enc,
        unit: unit, max_len: max_len, padding: padding, mask: mask,
        composite: COMPOSITE_NONE, tag_width: 0,
        pad_digit: 0, pad_char: -1, parent: 0, tag: 0,
    };
    return OK;
}

// True when the field is defined in the dialect.
fn dialect_has(d: Dialect&, id: i64) -> bool {
    if !valid_id(id) { return false; }
    return d.fields[id].defined;
}

// ---- composites ------------------------------------------------------

// Resolves a path to the key of a container. The key of a top-level
// container is its field id. The key of a container that is a subfield
// is 1000 plus the index of the sub.
fn resolve_container(d: Dialect&, p: Path) -> i64, i64 {
    if !path_valid(p) { return 0, ERR_BAD_ARG; }
    let fid = p.ids[0];
    if !valid_id(fid) { return 0, ERR_BAD_FIELD_ID; }
    if !d.fields[fid].defined { return 0, ERR_UNKNOWN_FIELD; }
    if d.fields[fid].composite == COMPOSITE_NONE { return 0, ERR_BAD_ARG; }
    var cont = fid;
    for i in 1..p.n {
        let si = find_sub(d, cont, p.ids[i]);
        if si < 0 { return 0, ERR_BAD_TAG; }
        if d.subs[si].composite == COMPOSITE_NONE { return 0, ERR_BAD_ARG; }
        cont = 1000 + si;
    }
    return cont, OK;
}

// Makes the field or the subfield at the path a container. The mode is
// COMPOSITE_LIST, COMPOSITE_TAGGED or COMPOSITE_BER. The tag width is
// the count of ASCII digits of a tag, and only a tagged container uses
// it. The dialect stays unchanged on a fault.
fn dialect_composite(d: Dialect&, path: Path, mode: i64, tag_width: i64) -> i64 {
    if mode != COMPOSITE_LIST && mode != COMPOSITE_TAGGED && mode != COMPOSITE_BER { return ERR_BAD_ARG; }
    if !path_valid(path) { return ERR_BAD_ARG; }
    if path.n > MAX_DEPTH { return ERR_DEPTH; }
    if mode == COMPOSITE_TAGGED {
        if tag_width < 1 || tag_width > 4 { return ERR_BAD_ARG; }
    } else if tag_width != 0 {
        return ERR_BAD_ARG;
    }
    if path.n == 1 {
        let fid = path.ids[0];
        if !valid_id(fid) { return ERR_BAD_FIELD_ID; }
        if !d.fields[fid].defined { return ERR_UNKNOWN_FIELD; }
        if mode == COMPOSITE_BER && d.fields[fid].enc != ENC_BINARY { return ERR_BAD_ARG; }
        d.fields[fid].composite = mode;
        d.fields[fid].tag_width = tag_width;
        return OK;
    }
    var parent = path;
    parent.n = path.n - 1;
    let cont, f = resolve_container(d, parent);
    if f != OK { return f; }
    let si = find_sub(d, cont, path.ids[path.n - 1]);
    if si < 0 { return ERR_BAD_TAG; }
    // The payload of a nested container is its own wire form, so the
    // encoding must not change the bytes.
    if d.subs[si].enc != ENC_ASCII && d.subs[si].enc != ENC_BINARY { return ERR_BAD_ARG; }
    if mode == COMPOSITE_BER && d.subs[si].enc != ENC_BINARY { return ERR_BAD_ARG; }
    d.subs[si].composite = mode;
    d.subs[si].tag_width = tag_width;
    return OK;
}

// Chooses the EBCDIC code page of the dialect. The default is 500.
// The dialect stays unchanged on a fault.
fn dialect_set_page(d: Dialect&, page: i64) -> i64 {
    if page != PAGE_500 && page != PAGE_037 && page != PAGE_1047 { return ERR_BAD_ARG; }
    d.page = page;
    return OK;
}

// The count of the used subfield specs of the dialect.
fn total_subs(d: Dialect&) -> i64 {
    var n = 0;
    for i in 0..192 {
        if d.subs[i].defined { n += 1; }
    }
    return n;
}

// Sets the pad rules of a field or a subfield. The pad digit is the pad
// nibble of an odd BCD or hex value: 0 to 15, 0 as the default. The pad
// character is the pad of a fixed text field: a byte of the alphabet,
// or -1 for none. The side comes from the padding of the field. The
// dialect stays unchanged on a fault.
fn dialect_field_pad(d: Dialect&, path: Path, pad_digit: i64, pad_char: i64) -> i64 {
    if pad_digit < 0 || pad_digit > 15 { return ERR_BAD_ARG; }
    if pad_char != -1 && (pad_char < 0x20 || pad_char > 0x7E) { return ERR_BAD_ARG; }
    if !path_valid(path) { return ERR_BAD_ARG; }
    var spec = FieldSpec { .. };
    var si = -1;
    if path.n == 1 {
        let fid = path.ids[0];
        if !valid_id(fid) { return ERR_BAD_FIELD_ID; }
        if !d.fields[fid].defined { return ERR_UNKNOWN_FIELD; }
        spec = d.fields[fid];
    } else {
        var parent = path;
        parent.n = path.n - 1;
        let cont, f = resolve_container(d, parent);
        if f != OK { return f; }
        si = find_sub(d, cont, path.ids[path.n - 1]);
        if si < 0 { return ERR_BAD_TAG; }
        spec = d.subs[si];
    }
    if pad_char != -1 {
        if spec.kind != KIND_FIXED { return ERR_BAD_ARG; }
        if spec.enc != ENC_ASCII && spec.enc != ENC_EBCDIC { return ERR_BAD_ARG; }
        // The pad character must sit in the alphabet of the encoding.
        var probe: u8[>..] = [];
        probe.push(pad_char as u8);
        if check_alphabet(spec.enc, probe) != OK { return ERR_BAD_ARG; }
    } else if pad_digit != 0 && !is_nibble_enc(spec.enc) {
        return ERR_BAD_ARG;
    }
    if path.n == 1 {
        d.fields[path.ids[0]].pad_digit = pad_digit;
        d.fields[path.ids[0]].pad_char = pad_char;
    } else {
        d.subs[si].pad_digit = pad_digit;
        d.subs[si].pad_char = pad_char;
    }
    return OK;
}

// Adds one subfield to the container at the parent path. The tag is the
// tag value, or the position in a list. The dialect stays unchanged on
// a fault.
fn dialect_sub(d: Dialect&, parent: Path, tag: i64, kind: i64, enc: i64, prefix_enc: i64, unit: i64, max_len: i64, padding: i64, mask: i64) -> i64 {
    if !path_valid(parent) { return ERR_BAD_ARG; }
    let cont, f = resolve_container(d, parent);
    if f != OK { return f; }
    if parent.n > MAX_DEPTH { return ERR_DEPTH; }
    let mode = container_spec(d, cont).composite;
    if sub_count(d, cont) >= MAX_SUBS_PER { return ERR_BAD_ARG; }
    if total_subs(d) >= MAX_SUBS { return ERR_BAD_ARG; }
    if kind < KIND_FIXED || kind > KIND_LLLVAR { return ERR_BAD_ARG; }
    if enc < ENC_ASCII || enc > ENC_HEX { return ERR_BAD_ARG; }
    if unit != UNIT_BYTES && unit != UNIT_NIBBLES { return ERR_BAD_ARG; }
    if padding != PAD_LEFT && padding != PAD_RIGHT { return ERR_BAD_ARG; }
    if mask < MASK_NONE || mask > MASK_INHERIT { return ERR_BAD_ARG; }
    if kind != KIND_FIXED {
        if prefix_enc < ENC_ASCII || prefix_enc > ENC_BINARY { return ERR_BAD_ARG; }
    }
    if unit == UNIT_NIBBLES && !is_nibble_enc(enc) { return ERR_BAD_ARG; }
    var bound = MAX_FIELD;
    if mode != COMPOSITE_BER {
        bound = prefix_cap(prefix_enc, kind);
    }
    if max_len < 1 || max_len > bound { return ERR_BAD_ARG; }
    var use_tag = 0;
    if mode == COMPOSITE_LIST {
        use_tag = sub_count(d, cont) + 1;
    } else if mode == COMPOSITE_TAGGED {
        let cs = container_spec(d, cont);
        var lim = 1;
        for i in 0..cs.tag_width { lim = lim * 10; }
        if tag < 0 || tag >= lim { return ERR_BAD_TAG; }
        use_tag = tag;
    } else {
        if ber_tag_len(tag) < 0 { return ERR_BAD_TAG; }
        if enc != ENC_ASCII && enc != ENC_BINARY { return ERR_BAD_ARG; }
        use_tag = tag;
    }
    if mode != COMPOSITE_LIST && find_sub(d, cont, use_tag) >= 0 { return ERR_DUPLICATE; }
    var slot = -1;
    for i in 0..192 {
        if !d.subs[i].defined { slot = i; break; }
    }
    if slot < 0 { return ERR_BAD_ARG; }
    d.subs[slot] = FieldSpec {
        defined: true, kind: kind, enc: enc, prefix_enc: prefix_enc,
        unit: unit, max_len: max_len, padding: padding, mask: mask,
        composite: COMPOSITE_NONE, tag_width: 0,
        pad_digit: 0, pad_char: -1, parent: cont, tag: use_tag,
    };
    return OK;
}

namespace iso8583;

import std;

// True when id names a field that a caller may set: 2 to the top field,
// without the field that holds the secondary bitmap indicator.
fn valid_id(id: i64) -> bool {
    return id >= 2 && id <= MAX_FIELD_ID && id != 65;
}

// OK when v is a legal MTI: four ASCII digits.
fn mti_ok(v: const u8[:]) -> bool {
    if v.len != 4 { return false; }
    for i in 0..4 { if !is_digit(v[i]) { return false; } }
    return true;
}

// Empties a message and zeroes the old bytes. Only the buffer of this
// value is cleared. Copies that the caller made stay as they are.
fn message_clear(msg: Message&) {
    fill(msg.data, 0);
    msg.data.clear();
    msg.mti.clear();
    msg.fault_field = 0;
    for i in 0..193 { msg.slots[i] = Slot { .. }; }
}

// Sets the MTI: four ASCII digits in the logical form.
fn message_set_mti(msg: Message&, mti: const u8[:]) -> i64 {
    if !mti_ok(mti) { return ERR_BAD_MTI; }
    msg.mti.clear();
    msg.mti.append(mti);
    return OK;
}

// OK when v is a legal value of the field under the dialect. Set and pack
// both use it, so a value set under one dialect cannot slip into another.
fn check_value(d: Dialect&, id: i64, v: const u8[:]) -> i64 {
    if !valid_id(id) { return ERR_BAD_FIELD_ID; }
    if !d.fields[id].defined { return ERR_UNKNOWN_FIELD; }
    let spec = d.fields[id];
    let maxv = value_len(spec.enc, spec.unit, spec.max_len);
    if v.len > maxv { return ERR_VALUE_LENGTH; }
    if spec.kind == KIND_FIXED && v.len != maxv { return ERR_VALUE_LENGTH; }
    if units_of(spec.enc, spec.unit, v.len) < 0 { return ERR_VALUE_LENGTH; }
    return check_alphabet(spec.enc, v);
}

// Removes the bytes of one field and closes the hole.
fn slot_drop(msg: Message&, id: i64) {
    if !msg.slots[id].present { return; }
    var keep: u8[>..] = [];
    for k in 2..193 {
        if !msg.slots[k].present { continue; }
        let s = msg.slots[k];
        if k == id { continue; }
        msg.slots[k].off = keep.len;
        keep.append(msg.data[s.off..s.off + s.len]);
    }
    msg.slots[id] = Slot { .. };
    fill(msg.data, 0);
    msg.data.clear();
    msg.data.append(keep);
}

// Sets a field. The value must fit the dialect. A second set replaces the
// first. The message data stays within MAX_INPUT bytes.
fn message_set(msg: Message&, d: Dialect&, id: i64, v: const u8[:]) -> i64 {
    let f = check_value(d, id, v);
    if f != OK { return f; }
    var live: i64 = 0;
    for k in 2..193 {
        if msg.slots[k].present && k != id { live += msg.slots[k].len; }
    }
    if live + v.len > MAX_INPUT { return ERR_FULL; }
    slot_drop(msg, id);
    msg.slots[id] = Slot { present: true, off: msg.data.len, len: v.len };
    msg.data.append(v);
    return OK;
}

// Copies the value of a field into out.
fn message_get(msg: Message&, id: i64, out: u8[>..]&) -> i64 {
    out.clear();
    if id < 2 || id > MAX_FIELD_ID { return ERR_BAD_FIELD_ID; }
    let s = msg.slots[id];
    if !s.present { return ERR_NOT_SET; }
    if s.off < 0 || s.len < 0 || s.off + s.len > msg.data.len { return ERR_BAD_ARG; }
    out.append(msg.data[s.off..s.off + s.len]);
    return OK;
}

fn message_has(msg: Message&, id: i64) -> bool {
    if !valid_id(id) { return false; }
    return msg.slots[id].present;
}

// Removes a field.
fn message_unset(msg: Message&, id: i64) -> i64 {
    if !valid_id(id) { return ERR_BAD_FIELD_ID; }
    if !msg.slots[id].present { return ERR_NOT_SET; }
    slot_drop(msg, id);
    return OK;
}

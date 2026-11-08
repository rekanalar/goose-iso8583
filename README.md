# goose-iso8583

[![ci](https://github.com/rekanalar/goose-iso8583/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-iso8583/actions/workflows/ci.yml)

ISO 8583 card messages for Goose. The package packs and unpacks the MTI, the bitmaps and the fields. The caller describes a network format as a dialect. A text form masks card data for logs.

## Install

Add this to the root file of the program that uses it:

```goose
import iso8583 from "rekanalar/goose-iso8583@v0.1.0";
```

## Quick start

```goose
import std;
import iso8583 from "rekanalar/goose-iso8583@v0.1.0";

fn main() {
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);

    var m = iso8583::Message { .. };
    let fault = iso8583::unpack(m, d, "02007000000000000000164111111111111111000000000000010000");
    if fault != iso8583::OK { return 1; }

    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);   // PAN shows as 411111******1111
    print(text);
    return 0;
}
```

## Dialects

A dialect holds the framing and a table of fields. Build it in code, or start from the default ASCII dialect and change fields on a copy. A dialect is a plain value, so `var e = d;` copies it.

| Setting | Values |
|---|---|
| MTI encoding | ASCII, EBCDIC (code page 500), BCD |
| Bitmap encoding | binary (8 bytes), hex ASCII (16), hex EBCDIC (16) |
| Bitmaps | 2, or 3 for a tertiary bitmap and the fields 129 to 192 |
| Field kind | fixed, LLVAR, LLLVAR |
| Data encoding | ASCII, EBCDIC, BCD, hex, binary |
| Prefix encoding | ASCII digits, EBCDIC digits, BCD, binary |
| Length unit | bytes, or nibbles for BCD and hex |
| Pad side | left or right, for a BCD or hex value with an odd digit count |
| Mask mode | none, PAN, full |

A message holds each value in its logical form. ASCII and EBCDIC fields hold text. BCD fields hold digit characters. Hex fields hold upper-case hex characters. Binary fields hold raw bytes. The codec converts to and from the wire form.

The prefix width follows the kind and the prefix encoding:

| Prefix encoding | LLVAR | LLLVAR |
|---|---|---|
| ASCII or EBCDIC digits | 2 bytes | 3 bytes |
| BCD | 1 byte (up to 99) | 2 bytes (up to 999) |
| Binary | 1 byte (up to 255) | 2 bytes (up to 999) |

A BCD or hex value with an odd digit count gets one pad nibble. The pad nibble is always 0. Unpack refuses a pad nibble that is not 0.

The package owns field 1 and field 65. Pack sets them from the fields that are present. A dialect cannot define them.

## API

Every call returns an `i64` fault code. `iso8583::OK` is 0. After a failed `unpack` the message is empty, and `msg.fault_field` names the field of the fault. It is 0 for the MTI, the bitmaps and the input as a whole.

| Call | Purpose |
|---|---|
| `dialect_init(d, mti_enc, bitmap_enc, bitmaps)` | Clear a dialect and set its framing. |
| `dialect_field(d, id, kind, enc, prefix_enc, unit, max_len, padding, mask)` | Define one field. Checks every argument. |
| `dialect_default_ascii(d)` | Fill the default ASCII dialect. |
| `dialect_has(d, id)` | True when the field is defined. |
| `message_clear(msg)` | Empty a message and zero its bytes. |
| `message_set_mti(msg, mti)` | Set the MTI, four digits. |
| `message_set(msg, d, id, value)` | Set a field. Checks length and alphabet. |
| `message_get(msg, id, out)` | Copy a field value into `out`. |
| `message_has(msg, id)` | True when the field is present. |
| `message_unset(msg, id)` | Remove a field. |
| `pack(out, msg, d)` | Message to bytes. |
| `unpack(msg, d, input)` | Bytes to message. |
| `message_text(out, msg, d)` | Masked text form for logs. |
| `mask_pan(out, digits)` | Mask a card number: first six and last four at most. |
| `frame_write(out, header, body)` | Add a network header. |
| `frame_read_length(header, input)` | Read the body length. Returns the length, then the fault code. |

The default ASCII dialect has a four-digit ASCII MTI and hex bitmaps of 16 characters. It defines the fields 2 to 128 of ISO 8583:1987. Its field table equals the `default_ascii` table of pyiso8583.

Network headers: `HEADER_NONE`, `HEADER_ASCII4` (four ASCII digits), `HEADER_BCD2` (two BCD bytes) and `HEADER_BINARY2` (two binary bytes). The header holds the length of the body.

## Fault codes

| Code | Meaning |
|---|---|
| `ERR_TOO_LONG` | The input or a value is above a limit. |
| `ERR_TRUNCATED` | The input ends inside an element. |
| `ERR_BAD_BYTE` | A byte is outside the alphabet of the encoding. |
| `ERR_BAD_LENGTH` | A prefix is not a number, or is above the field maximum. |
| `ERR_UNKNOWN_FIELD` | A bitmap bit has no field in the dialect. |
| `ERR_TRAILING` | Bytes follow the last field. |
| `ERR_BAD_ARG` | A dialect argument is bad. |
| `ERR_BAD_FIELD_ID` | A field id is out of range. |
| `ERR_VALUE_LENGTH` | A value length is not allowed for the field. |
| `ERR_BAD_MTI` | The MTI is missing, or is not four digits. |
| `ERR_NOT_SET` | The field is not present. |
| `ERR_BAD_BITMAP` | A bitmap bit that the dialect forbids. |
| `ERR_FULL` | The message data buffer is at its limit. |

## Limits

- No PIN blocks (ISO 9564), no key management and no MAC computation. Field 52 and the MAC fields are plain bytes to this package. Use a hardware security module for these tasks.
- No composite or TLV subfields, such as EMV data in field 55. The value is one byte string. moov-io/iso8583 and jPOS parse subfields.
- No track 1, 2 or 3 parsing.
- Only the ISO 8583:1987 field set is built in. The 1993 and 2003 editions need a dialect that the caller writes.
- Only code page 500 for EBCDIC. The 128 ASCII characters map one to one. Any other byte is a fault. moov-io/iso8583 also has code pages 037 and 1047.
- A hex bitmap in lower case is a fault. pyiso8583 accepts it.
- Padding uses the zero nibble only. pyiso8583 accepts any pad digit.
- The VML network header of moov-io/iso8583 is not built in.
- No JSON import or export, no struct binding and no stream reader. The package takes no socket calls.
- A message holds at most 65,535 bytes. A field value holds at most 999 units.
- A valid message does not prove that the transaction is real. The package checks the format only.

## Security

References: moov-io/iso8583 (Go), pyiso8583 (Python), jPOS (Java).

Protections beyond the references:

- Every call checks the input size (65,535 bytes) before any other work. The references set no such limit.
- A dialect call checks every argument. A bad length or prefix width fails when the caller builds the dialect. It does not fail when a message arrives.
- Unpack faults on trailing bytes. It also faults on a bitmap bit with no field. It faults on a byte outside the alphabet of the encoding. moov-io/iso8583 does not compare the last offset with the input length.
- Pack checks every value against the dialect it receives. A value set under another dialect cannot give a wrong length prefix.
- A fault holds a code and a field id. It never holds value bytes. pyiso8583 puts the whole input and the decoded fields in its exception.
- After a failed unpack the message is empty, so a half-read PAN does not stay in it.
- The text form masks fields by dialect mask mode. The default dialect masks fields 2, 34, 102 and 103 as a PAN. A PAN shows the first six and last four digits at most. The default dialect masks fields 35, 36, 45, 52, 53 and 55 in full. A field that the dialect does not define is masked in full. moov-io/iso8583 writes every value in clear in its JSON output.
- The text form replaces a byte that is not printable ASCII with a dot. A value cannot add a line to a log.
- `message_clear` zeroes the data buffer of the message.

Risks that stay:

- A message holds the PAN and other card data in memory in clear. Use `message_text` to log it. The package has no call that makes memory copies disappear. The runtime may copy a value.
- The `value` that the caller passes to `message_get` is a copy. The caller must protect it.
- A dialect that the caller writes can mark a secret field with mask mode none. The package prints what the dialect allows.
- A valid message can still be a forgery. The package does not check a MAC.

## License

MIT

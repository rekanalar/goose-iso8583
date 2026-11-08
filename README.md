# goose-iso8583

[![ci](https://github.com/rekanalar/goose-iso8583/actions/workflows/ci.yml/badge.svg)](https://github.com/rekanalar/goose-iso8583/actions/workflows/ci.yml)

ISO 8583 card messages for Goose. The package packs and unpacks the MTI, the bitmaps and the fields. The caller describes a network format as a dialect. A text form masks card data for logs.

## Install

Add this to the root file of the program that uses it:

```goose
import iso8583 from "rekanalar/goose-iso8583@v0.2.0";
```

## Quick start

```goose
import std;
import iso8583 from "rekanalar/goose-iso8583@v0.2.0";

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

A dialect holds the framing and a table of fields. Build it in code, or start from a default dialect and change fields on a copy. A dialect is a plain value, so `var e = d;` copies it.

| Setting | Values |
|---|---|
| MTI encoding | ASCII, EBCDIC, BCD |
| Bitmap encoding | binary (8 bytes), hex ASCII (16), hex EBCDIC (16) |
| Bitmaps | 2, or 3 for a tertiary bitmap and the fields 129 to 192 |
| Field kind | fixed, LLVAR, LLLVAR |
| Data encoding | ASCII, EBCDIC, BCD, hex, binary |
| Prefix encoding | ASCII digits, EBCDIC digits, BCD, binary |
| Length unit | bytes, or nibbles for BCD and hex |
| Pad side | left or right, for a BCD or hex value with an odd digit count |
| Mask mode | none, PAN, full, inherit (subfields only) |

A message holds each value in its logical form. ASCII and EBCDIC fields hold text. BCD fields hold digit characters. Hex fields hold upper-case hex characters. Binary fields hold raw bytes. The codec converts to and from the wire form.

The prefix width follows the kind and the prefix encoding:

| Prefix encoding | LLVAR | LLLVAR |
|---|---|---|
| ASCII or EBCDIC digits | 2 bytes | 3 bytes |
| BCD | 1 byte (up to 99) | 2 bytes (up to 999) |
| Binary | 1 byte (up to 255) | 2 bytes (up to 999) |

A BCD or hex value with an odd digit count gets one pad nibble. The pad nibble is 0 by default. A dialect can name another pad digit from 0 to 15. Unpack refuses a pad nibble that differs from the declared one.

A fixed text field can name a pad character. Pack fills the free space with it. Unpack removes the run of pad characters on the declared side. The package refuses a value that starts with the left pad character or ends with the right one. Such a value cannot round trip.

The package owns field 1 and field 65. Pack sets them from the fields that are present. A dialect cannot define them.

## Code pages

An EBCDIC dialect uses one code page. The page holds the 128 ASCII characters. Any other byte is a fault.

| Page | Name |
|---|---|
| `PAGE_500` | IBM code page 500, the default |
| `PAGE_037` | IBM code page 037 |
| `PAGE_1047` | IBM code page 1047 |

Call `dialect_set_page` to choose the page of a dialect. The tables come from the `cp500` and `cp037` codecs of Python and from `iconv` for page 1047. The generator checks each table against a second source and fails on a difference.

## Composite fields

A field can hold subfields. The dialect declares the container and its subfields. A path names one subfield: the field id, then one tag or position per level.

| Mode | Wire form |
|---|---|
| `COMPOSITE_LIST` | The subfields in the order of their declaration. All of them are there. |
| `COMPOSITE_TAGGED` | A tag of ASCII digits, then the value. Any subset of the subfields. |
| `COMPOSITE_BER` | A BER tag, a BER length, then the value. Any subset of the subfields. |

```goose
var d = iso8583::Dialect { .. };
iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                       iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL);
iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_BER, 0);
iso8583::dialect_sub(d, iso8583::path1(55), 0x5F2A, iso8583::KIND_FIXED, iso8583::ENC_BINARY, 0,
                     iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);

var v: u8[>..] = [];
iso8583::message_get_sub(m, d, iso8583::path2(55, 0x5F2A), v);
```

The BER rules of the package:

| Item | Rule |
|---|---|
| Tag | One byte, or more when the low five bits of the first byte are all set. At most three bytes. |
| Length | One byte below 128. `81 xx` for 128 to 255. `82 xx xx` for 256 to 999. |
| Length form | A length takes its shortest form. A longer form is `ERR_BAD_LENGTH`. |
| Indefinite length | `80` gives `ERR_BAD_LENGTH`. |
| Duplicate tag | `ERR_DUPLICATE`. |
| Unknown tag | `ERR_BAD_TAG`. |

A container holds at most 64 subfields and 999 bytes of payload. The nesting goes three levels deep. A container above the limit gives `ERR_DEPTH` when the caller builds the dialect.

The package keeps the order of the wire. A set of a new tag puts that tag last. A set of a known tag keeps its place. The package never sorts the subfields, so unpack and pack give the same bytes.

A subfield with a pad character takes 0 to `max_len` characters, like a field. The container keeps the pad on the wire. The value of the subfield has no pad.

## Track data

The package parses and builds the magnetic stripe tracks.

| Part | Track 1 | Track 2 |
|---|---|---|
| Start | One format letter | None |
| PAN | 1 to 19 digits | 1 to 19 digits |
| Separator | `^` | `=` or `D` |
| Name | 2 to 26 characters | None |
| Expiry | 4 digits, or `^` | 4 digits |
| Service code | 3 digits, or `^` | 3 digits |
| Discretionary | 0 to 79 characters | 0 to 40 characters |

A track that breaks a rule gives `ERR_BAD_TRACK`. The parts stay empty, so a fault never holds track bytes. The text form of a track field stays fully masked.

## Stream reader

The reader takes the bytes of a stream as they arrive and yields whole message bodies. It holds one frame at most.

```goose
var r = iso8583::Reader { .. };
iso8583::reader_init(r, iso8583::HEADER_ASCII4);
while data.len > 0 {
    let n, f = iso8583::reader_feed(r, data);
    if f != iso8583::OK { break; }
    data = data[n..];
    if iso8583::reader_ready(r) {
        var body: u8[>..] = [];
        iso8583::reader_take(r, body);
        iso8583::unpack(m, d, body);
    }
}
```

The reader reads the length in the header before it stores a body byte. A bad header gives a fault and locks the reader. The reader stays locked until `reader_reset` clears it. `HEADER_NONE` gives `ERR_BAD_ARG`, because a body without a length has no split points.

## API

Every call returns an `i64` fault code. `iso8583::OK` is 0. After a failed `unpack` the message is empty, and `msg.fault_field` names the field of the fault. It is 0 for the MTI, the bitmaps and the input as a whole.

| Call | Purpose |
|---|---|
| `dialect_init(d, mti_enc, bitmap_enc, bitmaps)` | Clear a dialect and set its framing. |
| `dialect_field(d, id, kind, enc, prefix_enc, unit, max_len, padding, mask)` | Define one field. Checks every argument. |
| `dialect_set_page(d, page)` | Choose the EBCDIC code page. |
| `dialect_field_pad(d, path, pad_digit, pad_char)` | Set the pad digit and the pad character. |
| `dialect_composite(d, path, mode, tag_width)` | Make a field a container of subfields. |
| `dialect_sub(d, parent, tag, kind, enc, prefix_enc, unit, max_len, padding, mask)` | Add one subfield. |
| `dialect_default_ascii(d)` | Fill the default ASCII dialect of ISO 8583:1987. |
| `dialect_default_1993_ascii(d)` | Fill the ASCII dialect of ISO 8583:1993. |
| `dialect_default_1993_binary(d)` | Fill the BCD and binary dialect of ISO 8583:1993. |
| `dialect_has(d, id)` | True when the field is defined. |
| `path1(id)` to `path4(id, a, b, c)` | Build a path to a subfield. |
| `message_clear(msg)` | Empty a message and zero its bytes. |
| `message_set_mti(msg, mti)` | Set the MTI, four digits. |
| `message_set(msg, d, id, value)` | Set a field. Checks length and alphabet. |
| `message_get(msg, id, out)` | Copy a field value into `out`. |
| `message_has(msg, id)` | True when the field is present. |
| `message_unset(msg, id)` | Remove a field. |
| `message_get_sub(msg, d, path, out)` | Copy a subfield value into `out`. |
| `message_set_sub(msg, d, path, value)` | Set a subfield. Makes the container when it is absent. |
| `message_has_sub(msg, d, path)` | True when the subfield is present. |
| `message_unset_sub(msg, d, path)` | Remove a subfield. |
| `pack(out, msg, d)` | Message to bytes. |
| `unpack(msg, d, input)` | Bytes to message. |
| `message_text(out, msg, d)` | Masked text form for logs. |
| `mask_pan(out, digits)` | Mask a card number: first six and last four at most. |
| `track1_parse(t, text)` | Parse a track 1 string. |
| `track1_build(out, t)` | Build a track 1 string. |
| `track2_parse(t, text)` | Parse a track 2 string. |
| `track2_build(out, t)` | Build a track 2 string. |
| `reader_init(r, header)` | Start a reader for a header kind. |
| `reader_feed(r, input)` | Take bytes up to the end of the frame. Returns the count, then the fault code. |
| `reader_ready(r)` | True when a whole body waits. |
| `reader_take(r, out)` | Move the body to `out`. |
| `reader_reset(r)` | Clear the buffer and the fault. |
| `frame_write(out, header, body)` | Add a network header. |
| `frame_read_length(header, input)` | Read the body length. Returns the length, then the fault code. |

The default ASCII dialect has a four-digit ASCII MTI and hex bitmaps of 16 characters. It defines the fields 2 to 128 of ISO 8583:1987. Its field table equals the `default_ascii` table of pyiso8583.

The two dialects of ISO 8583:1993 hold the field table of the ISO93A and ISO93B packagers of the jPOS project. The generator reads those sources as text and writes numbers only. The A variant is plain ASCII. The B variant uses BCD digits and binary bytes, and its bitmap is binary. The two variants differ in more than the encoding. Field 39 holds three digits in 1993, where it holds two in 1987.

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
| `ERR_DUPLICATE` | The same tag stands twice in one container. |
| `ERR_BAD_TAG` | A tag has no subfield, or a bad form. |
| `ERR_DEPTH` | The nesting is above the limit of three levels. |
| `ERR_BAD_TRACK` | The track text does not match the track rules. |
| `ERR_STREAM` | The reader holds a fault. |

## Limits

- No PIN blocks (ISO 9564), no key management and no MAC computation. Field 52 and the MAC fields are plain bytes to this package. Use a hardware security module for these tasks.
- A composite field holds a list of subfields, a tagged list or a BER-TLV container. It has no bitmap mode, where a bitmap names the present subfields. moov-io/iso8583 has that mode.
- A container keeps the order of the wire. It never sorts the subfields by tag.
- A BER length takes its shortest form. moov-io/iso8583 accepts a longer form.
- The nesting goes three levels deep, and a container holds 64 subfields and 999 bytes.
- No track 3 parsing. The ISO 8583:1993 table holds field 36 as a plain value.
- The ISO 8583:1993 table is built in, in an ASCII and a BCD variant. No reference holds a table that it labels as ISO 8583:2003. pyiso8583 and moov-io/iso8583 ship only the 1987 table, and moov-io/iso8583 names 2003 in its docs without one.
- One code page per dialect. A page per field is not built in. moov-io/iso8583 has no code page 037, and pyiso8583 takes any Python codec, so it has no fixed table either.
- A hex bitmap in lower case is a fault. pyiso8583 accepts it.
- A fixed field with a pad character takes 0 to `max_len` characters. The first release took exactly `max_len` characters for every fixed field.
- The text form of the fields 48 and 120 to 127 shows stars. The first release showed the value of those fields.
- The VML network header of moov-io/iso8583 is not built in.
- No JSON import or export, and no struct binding.
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
- The text form masks fields by dialect mask mode. The default dialect masks fields 2, 34, 102 and 103 as a PAN.
- A PAN shows the first six and last four digits at most. The default dialect masks fields 35, 36, 45, 48, 52, 53, 55 and 120 to 127 in full.
- Fields 48 and 120 to 127 hold private network data of an unknown shape, so the default masks them. A field that the dialect does not define is masked in full. moov-io/iso8583 writes every value in clear in its JSON output.
- Each subfield of a composite field has its own mask mode. A subfield with mode inherit takes the mode of the nearest container that sets one. A composite field shows as one masked line, and its subfields show one line each.
- The text form replaces a byte that is not printable ASCII with a dot. A value cannot add a line to a log.
- The reader checks the length in the header before it stores a body byte. A header that names a length above the limit faults at once. moov-io/iso8583 reads a signed number in its ASCII header.
- The reader locks after a fault. It holds no bytes of the frame, and it takes no input until the caller resets it.
- A track fault never holds track bytes, and the parts of a track stay empty after a fault.
- The package refuses a value that starts with the left pad character or ends with the right one. Such a value does not round trip. The references accept it.
- The pad digit on the wire must match the digit that the dialect names. A value cannot change its length on the wire.
- A BER length takes its shortest form. moov-io/iso8583 accepts a longer form. That gives two wire forms for one value.
- `message_clear` zeroes the data buffer of the message.

Risks that stay:

- A message holds the PAN and other card data in memory in clear. The same holds for the values of a composite field. Use `message_text` to log it. The package has no call that makes memory copies disappear. The runtime may copy a value.
- The `value` that the caller passes to `message_get` is a copy. The caller must protect it.
- A dialect that the caller writes can mark a secret field with mask mode none. The package prints what the dialect allows.
- A subfield with mask mode none shows its value, even when its container is masked. The mode of the container covers the line of the container alone. A subfield that must stay hidden takes the mode inherit.
- A valid message can still be a forgery. The package does not check a MAC.

## License

MIT

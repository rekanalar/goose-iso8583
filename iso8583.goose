// iso8583 - ISO 8583 card messages for Goose.
//
// The package packs and unpacks messages: the MTI, the bitmaps and the
// fields 2 to 192. The caller describes a network format as a Dialect.
// Every public call returns a fault code and never aborts.
//
// The repository is goose-iso8583. The import name is "iso8583". Every
// file of the package declares that namespace.
namespace iso8583;

import std;
import text;
import ebcdic;
import codec;
import dialect;
import default_dialect;
import message;
import pack;
import unpack;
import mask;
import frame;
import composite;
import track;
import stream;
import default_dialect93;

// Data and prefix encodings.
const ENC_ASCII: i64 = 0;
const ENC_EBCDIC: i64 = 1;
const ENC_BCD: i64 = 2;
const ENC_BINARY: i64 = 3;
const ENC_HEX: i64 = 4;

// Bitmap encodings.
const BITMAP_BINARY: i64 = 0;
const BITMAP_HEX_ASCII: i64 = 1;
const BITMAP_HEX_EBCDIC: i64 = 2;

// Field kinds. The kind sets the width of the length prefix.
const KIND_FIXED: i64 = 0;
const KIND_LLVAR: i64 = 1;
const KIND_LLLVAR: i64 = 2;

// Length units for BCD and hex fields.
const UNIT_BYTES: i64 = 0;
const UNIT_NIBBLES: i64 = 1;

// Side of the padding nibble in a BCD or hex value with an odd digit count.
const PAD_LEFT: i64 = 0;
const PAD_RIGHT: i64 = 1;

// Mask modes of the text form. MASK_INHERIT is for subfields only: it
// takes the mode of the nearest container that sets another mode.
const MASK_NONE: i64 = 0;
const MASK_PAN: i64 = 1;
const MASK_FULL: i64 = 2;
const MASK_INHERIT: i64 = 3;

// Composite field modes. A composite field holds subfields.
const COMPOSITE_NONE: i64 = 0;
const COMPOSITE_LIST: i64 = 1;
const COMPOSITE_TAGGED: i64 = 2;
const COMPOSITE_BER: i64 = 3;

// EBCDIC code pages. The default is 500.
const PAGE_500: i64 = 0;
const PAGE_037: i64 = 1;
const PAGE_1047: i64 = 2;

// Limits of the composite and stream features. A call checks them before
// any work that depends on them.
const MAX_DEPTH: i64 = 3;
const MAX_SUBS: i64 = 192;
const MAX_SUBS_PER: i64 = 64;
const MAX_PATH: i64 = 4;
const MAX_BUFFER: i64 = 65543;

// States of the stream reader.
const STATE_HEADER: i64 = 0;
const STATE_BODY: i64 = 1;
const STATE_READY: i64 = 2;
const STATE_FAULT: i64 = 3;

// Network header kinds.
const HEADER_NONE: i64 = 0;
const HEADER_ASCII4: i64 = 1;
const HEADER_BCD2: i64 = 2;
const HEADER_BINARY2: i64 = 3;

// Limits. A call checks them before any other work.
const MAX_INPUT: i64 = 65535;
const MAX_FIELD: i64 = 999;
const MAX_FIELD_ID: i64 = 192;

// Fault codes. OK is zero.
const OK: i64 = 0;
const ERR_TOO_LONG: i64 = 1;
const ERR_TRUNCATED: i64 = 2;
const ERR_BAD_BYTE: i64 = 3;
const ERR_BAD_LENGTH: i64 = 4;
const ERR_UNKNOWN_FIELD: i64 = 5;
const ERR_TRAILING: i64 = 6;
const ERR_BAD_ARG: i64 = 7;
const ERR_BAD_FIELD_ID: i64 = 8;
const ERR_VALUE_LENGTH: i64 = 9;
const ERR_BAD_MTI: i64 = 10;
const ERR_NOT_SET: i64 = 11;
const ERR_BAD_BITMAP: i64 = 12;
const ERR_FULL: i64 = 13;
const ERR_DUPLICATE: i64 = 14;
const ERR_BAD_TAG: i64 = 15;
const ERR_DEPTH: i64 = 16;
const ERR_BAD_TRACK: i64 = 17;
const ERR_STREAM: i64 = 18;

// The description of one field or one subfield. The kind sets the width
// of the length prefix. max_len counts units: characters for ASCII and
// EBCDIC, bytes for binary, and digits (unit nibbles) or wire bytes (unit
// bytes) for BCD and hex. composite marks a container field. tag_width is
// the width in ASCII digits of a subfield tag in a COMPOSITE_TAGGED
// container. pad_digit is the pad nibble of an odd BCD or hex value.
// pad_char is the pad character of a fixed text field, or -1 for none.
// parent and tag describe a subfield: parent is the index of its
// container (a field id, or 1000 plus the sub index for a nested
// container), tag is the tag value or the 1-based position.
struct FieldSpec {
    defined: bool,
    kind: i64,
    enc: i64,
    prefix_enc: i64,
    unit: i64,
    max_len: i64,
    padding: i64,
    mask: i64,
    composite: i64,
    tag_width: i64,
    pad_digit: i64,
    pad_char: i64,
    parent: i64,
    tag: i64,
}

// A network format. Index 0 and 1 of fields stay unused. subs holds the
// subfield specs; a used entry has parent above 0. page is the EBCDIC
// code page of the text fields.
struct Dialect {
    mti_enc: i64,
    bitmap_enc: i64,
    bitmaps: i64,
    page: i64,
    fields: FieldSpec[193],
    subs: FieldSpec[192],
}

// Where the value of one field sits in the data buffer of a message.
struct Slot {
    present: bool,
    off: i64,
    len: i64,
}

// A message holds the PAN in memory in clear. Use message_text to log it.
// live is the sum of the lengths of the present slots. The growable
// buffer must be the last field of the struct.
struct Message {
    mti: u8[..8],
    fault_field: i64,
    live: i64,
    holes: i64,
    slots: Slot[193],
    data: u8[>..],
}

// A path to one subfield: the field id, then one tag or position per
// level below it.
struct Path {
    ids: i64[4],
    n: i64,
}

// The parts of one magnetic stripe track. The arrays are inline and
// bounded, so a fault never needs to clean up a growable value.
struct Track {
    kind: i64,
    has_expiry: bool,
    has_service: bool,
    format: u8[..1],
    pan: u8[..19],
    name: u8[..26],
    expiry: u8[..4],
    service: u8[..3],
    discretionary: u8[..79],
}

// An incremental reader for framed message bodies. The growable buffer
// must be the last field of the struct.
struct Reader {
    header: i64,
    state: i64,
    want: i64,
    buf: u8[>..],
}

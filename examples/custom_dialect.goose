// Describe a network format in code: EBCDIC text, BCD numbers, binary
// bitmaps and binary length prefixes. Then pack and unpack a message.
import std;
import iso8583 from "..";

fn show(bytes: const u8[:]) {
    let digits = "0123456789ABCDEF";
    var line: u8[>..] = [];
    for i in 0..bytes.len {
        line.push(digits[bytes[i] >> 4]);
        line.push(digits[bytes[i] & 15]);
    }
    print(line, "\n");
}

fn main() {
    var d = iso8583::Dialect { .. };
    iso8583::dialect_init(d, iso8583::ENC_BCD, iso8583::BITMAP_BINARY, 2);
    // Field 2: PAN, BCD digits, a one-byte BCD length that counts digits.
    iso8583::dialect_field(d, 2, iso8583::KIND_LLVAR, iso8583::ENC_BCD, iso8583::ENC_BCD,
                           iso8583::UNIT_NIBBLES, 19, iso8583::PAD_LEFT, iso8583::MASK_PAN);
    // Field 4: amount, 12 BCD digits in 6 bytes.
    iso8583::dialect_field(d, 4, iso8583::KIND_FIXED, iso8583::ENC_BCD, 0,
                           iso8583::UNIT_BYTES, 6, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    // Field 41: terminal id, 8 EBCDIC characters.
    iso8583::dialect_field(d, 41, iso8583::KIND_FIXED, iso8583::ENC_EBCDIC, 0,
                           iso8583::UNIT_BYTES, 8, iso8583::PAD_LEFT, iso8583::MASK_NONE);
    // Field 55: chip data, binary, a two-byte binary length.
    iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_BINARY,
                           iso8583::UNIT_BYTES, 255, iso8583::PAD_LEFT, iso8583::MASK_FULL);

    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0200");
    iso8583::message_set(m, d, 2, "4111111111111111");
    iso8583::message_set(m, d, 4, "000000012500");
    iso8583::message_set(m, d, 41, "TERM0001");
    var chip: u8[>..] = [];
    chip.push(0x9F);
    chip.push(0x26);
    chip.push(0x08);
    iso8583::message_set(m, d, 55, chip);

    var wire: u8[>..] = [];
    let fault = iso8583::pack(wire, m, d);
    if fault != iso8583::OK { print("pack failed: ", fault, "\n"); return 1; }
    show(wire);

    var back = iso8583::Message { .. };
    if iso8583::unpack(back, d, wire) != iso8583::OK { return 1; }
    var text: u8[>..] = [];
    iso8583::message_text(text, back, d);
    print(text);
    return 0;
}

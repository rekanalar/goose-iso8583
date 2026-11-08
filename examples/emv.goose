// Read the EMV data of field 55 as a BER-TLV container and build it back.
import std;
import iso8583 from "..";

// The EMV tags of the example: the application identifier, the currency
// code and the language preference.
fn emv_dialect(d: iso8583::Dialect&) -> i64 {
    var bad = 0;
    bad += iso8583::dialect_init(d, iso8583::ENC_ASCII, iso8583::BITMAP_HEX_ASCII, 2);
    bad += iso8583::dialect_field(d, 55, iso8583::KIND_LLLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                 iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_FULL);
    bad += iso8583::dialect_composite(d, iso8583::path1(55), iso8583::COMPOSITE_BER, 0);
    bad += iso8583::dialect_sub(d, iso8583::path1(55), 0x4F, iso8583::KIND_LLVAR, iso8583::ENC_BINARY, iso8583::ENC_ASCII,
                                iso8583::UNIT_BYTES, 999, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    bad += iso8583::dialect_sub(d, iso8583::path1(55), 0x5F2A, iso8583::KIND_FIXED, iso8583::ENC_BINARY, 0,
                                iso8583::UNIT_BYTES, 2, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    bad += iso8583::dialect_sub(d, iso8583::path1(55), 0x5F2D, iso8583::KIND_FIXED, iso8583::ENC_BINARY, 0,
                                iso8583::UNIT_BYTES, 4, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    bad += iso8583::dialect_sub(d, iso8583::path1(55), 0x9F02, iso8583::KIND_FIXED, iso8583::ENC_BINARY, 0,
                                iso8583::UNIT_BYTES, 6, iso8583::PAD_LEFT, iso8583::MASK_INHERIT);
    return bad;
}

fn main() {
    var d = iso8583::Dialect { .. };
    if emv_dialect(d) != iso8583::OK { return 1; }

    // Field 55 holds: 4F 07 A0000000041010, 5F2A 02 0840, 5F2D 04 7275656E,
    // 9F02 06 000000000100.
    var payload: u8[>..] = [];
    let bytes = "4F07A00000000410105F2A0208405F2D047275656E9F0206000000000100";
    var i = 0;
    while i < bytes.len {
        var v: i64 = 0;
        let c = bytes[i];
        if c >= '0' && c <= '9' { v = c - '0'; } else { v = c - 'A' + 10; }
        let d2 = bytes[i + 1];
        var w: i64 = 0;
        if d2 >= '0' && d2 <= '9' { w = d2 - '0'; } else { w = d2 - 'A' + 10; }
        payload.push((v * 16 + w) as u8);
        i += 2;
    }

    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0800");
    if iso8583::message_set(m, d, 55, payload) != iso8583::OK { return 1; }

    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);
    print(text, "\n");

    // Read one tag by its path.
    var currency: u8[>..] = [];
    if iso8583::message_get_sub(m, d, iso8583::path2(55, 0x5F2A), currency) == iso8583::OK {
        print("currency ", currency, "\n");
    }

    // Change the amount and build the message again.
    var amount: u8[>..] = [];
    for k in 0..6 { amount.push(0); }
    amount[4] = 0x02;
    amount[5] = 0x58;
    if iso8583::message_set_sub(m, d, iso8583::path2(55, 0x9F02), amount) != iso8583::OK { return 1; }

    var wire: u8[>..] = [];
    if iso8583::pack(wire, m, d) != iso8583::OK { return 1; }
    print("wire ", wire, "\n");
    return 0;
}

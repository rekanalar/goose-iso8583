// Log a message. The text form masks the card number and the secrets.
import std;
import iso8583 from "..";

fn main() {
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);
    var m = iso8583::Message { .. };
    iso8583::message_set_mti(m, "0100");
    iso8583::message_set(m, d, 2, "5500000000000004");
    iso8583::message_set(m, d, 3, "000000");
    iso8583::message_set(m, d, 4, "000000001999");
    iso8583::message_set(m, d, 35, "5500000000000004=25121010000000000");
    iso8583::message_set(m, d, 41, "TERM0001");
    iso8583::message_set(m, d, 52, "0123456789ABCDEF");

    var text: u8[>..] = [];
    iso8583::message_text(text, m, d);
    print(text);

    // A caller that needs a masked PAN alone calls mask_pan.
    var pan: u8[>..] = [];
    iso8583::mask_pan(pan, "5500000000000004");
    print("PAN ", pan, "\n");
    return 0;
}

// Unpack a message in the default ASCII dialect, change a field, pack it.
import std;
import iso8583 from "..";

fn main() {
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);

    // MTI 0200, bitmap for fields 2, 3 and 4, then the three fields.
    let wire = "02007000000000000000164111111111111111000000000000010000";
    var m = iso8583::Message { .. };
    let fault = iso8583::unpack(m, d, wire);
    if fault != iso8583::OK {
        print("unpack failed: code ", fault, " at field ", m.fault_field, "\n");
        return 1;
    }
    var amount: u8[>..] = [];
    iso8583::message_get(m, 4, amount);
    print("MTI ", m.mti, ", amount ", amount, "\n");

    // Turn the request into a response and add a response code.
    iso8583::message_set_mti(m, "0210");
    iso8583::message_set(m, d, 39, "00");
    var out: u8[>..] = [];
    let packed = iso8583::pack(out, m, d);
    if packed != iso8583::OK { return 1; }
    print(out, "\n");
    return 0;
}

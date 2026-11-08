// Frame two messages, feed them to the reader in pieces, and show each.
import std;
import iso8583 from "..";

fn main() {
    var d = iso8583::Dialect { .. };
    iso8583::dialect_default_ascii(d);

    // Two messages with the ASCII header.
    var one: u8[>..] = [];
    var two: u8[>..] = [];
    var m1 = iso8583::Message { .. };
    iso8583::message_set_mti(m1, "0200");
    iso8583::message_set(m1, d, 3, "000000");
    iso8583::pack(one, m1, d);
    var m2 = iso8583::Message { .. };
    iso8583::message_set_mti(m2, "0210");
    iso8583::message_set(m2, d, 39, "00");
    iso8583::pack(two, m2, d);

    var stream: u8[>..] = [];
    var framed: u8[>..] = [];
    iso8583::frame_write(framed, iso8583::HEADER_ASCII4, one);
    stream.append(framed);
    framed.clear();
    iso8583::frame_write(framed, iso8583::HEADER_ASCII4, two);
    stream.append(framed);

    var r = iso8583::Reader { .. };
    if iso8583::reader_init(r, iso8583::HEADER_ASCII4) != iso8583::OK { return 1; }

    // Feed the stream in pieces of seven bytes.
    var pos = 0;
    while pos < stream.len {
        var end = pos + 7;
        if end > stream.len { end = stream.len; }
        let piece = stream[pos..end];
        var used = 0;
        while used < piece.len {
            let rest = piece[used..piece.len];
            let n, f = iso8583::reader_feed(r, rest);
            if f != iso8583::OK { print("feed failed: ", f, "\n"); return 1; }
            used += n;
            if iso8583::reader_ready(r) {
                var body: u8[>..] = [];
                iso8583::reader_take(r, body);
                var back = iso8583::Message { .. };
                if iso8583::unpack(back, d, body) != iso8583::OK { print("unpack failed\n"); return 1; }
                var text: u8[>..] = [];
                iso8583::message_text(text, back, d);
                print(text, "\n");
            }
        }
        pos = end;
    }
    return 0;
}

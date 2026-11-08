// Parse a track 2 and a track 1, and show them with the PAN masked.
import std;
import iso8583 from "..";

fn main() {
    var t2 = iso8583::Track { .. };
    if iso8583::track2_parse(t2, "4000000000000001=25121010000000") != iso8583::OK { return 1; }
    var shown: u8[>..] = [];
    iso8583::mask_pan(shown, t2.pan);
    print("track 2: pan ", shown, ", expiry ", t2.expiry, ", service ", t2.service, "\n");

    var t1 = iso8583::Track { .. };
    if iso8583::track1_parse(t1, "B4000000000000001^CARDHOLDER^25121010000000") != iso8583::OK { return 1; }
    shown.clear();
    iso8583::mask_pan(shown, t1.pan);
    print("track 1: pan ", shown, ", name length ", t1.name.len, ", expiry ", t1.expiry, "\n");

    // A bad separator gives a fault code and an empty track.
    var bad = iso8583::Track { .. };
    let f = iso8583::track2_parse(bad, "4000000000000001-2512101");
    print("bad track: code ", f, ", pan length ", bad.pan.len, "\n");
    return 0;
}

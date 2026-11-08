import std;
import iso8583 from "..";
import suite from "./suite";

fn main() {
    var bad = 0;
    bad += suite::run_ref();
    bad += suite::run_codec();
    bad += suite::run_dialect();
    bad += suite::run_message();
    bad += suite::run_message_cost();
    bad += suite::run_message_compact();
    bad += suite::run_message_order();
    bad += suite::run_faults();
    bad += suite::run_pack_recheck();
    bad += suite::run_hostile();
    bad += suite::run_random();
    bad += suite::run_mask();
    bad += suite::run_frame();
    bad += suite::run_hygiene();
    bad += suite::run_composite();
    bad += suite::run_track();
    bad += suite::run_stream();
    bad += suite::run_pages();
    bad += suite::run_ref93();
    bad += suite::run_hostile2();
    bad += suite::run_pad();
    if bad > 0 { print(bad, " checks failed\n"); return 1; }
    print("ok\n");
    return 0;
}

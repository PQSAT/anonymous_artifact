#!/usr/bin/env python3
"""Adversary radio on the bench, for the over the air evidence of the attack classes.

The adversary holds a radio and nothing else (no key, no certificate).  It can hear a
channel and it can transmit on a channel with the COP-1 sequence number it has read from the
public CLCW, which is what any receiver on the link can do.  This tool records frames and
sends recorded or well formed frames again so that the satellite's acceptance checks can be
measured on real hardware.  The satellite's reaction is in the bridge window and in the
public housekeeping counters this tool prints before and after.

    python adversary.py --port COM5 record --seconds 120     record the frames on a channel
    python adversary.py --port COM5 replay                   send the recorded frames again
    python adversary.py --port COM5 replay --flip            each recorded frame with one bit changed

Add --sat2 for SAT-2's channel pair and --as-ground for the ground station's virtual channel.

The attack classes are catalogued in platform/pqsat_testbed/attacks12.py.  record and replay
give the over the air evidence for replay_handshake, forged_message and bit_flip (--flip).
The remaining classes are covered without a radio: man in the middle, downgrade, session
state and revocation by protocol/test_attacks_protocol.py, the two inter satellite classes by
flight/apps/sat_rf/test/test_isl_key_compromise.py, and the reassembly and air time classes
by test_reassembly_hold.py on the emulated link.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
from ccsds_link import (SerialLink, UPLINK_MHZ, DOWNLINK_MHZ, SAT2_UPLINK_MHZ,  # noqa: E402
                        SAT2_DOWNLINK_MHZ, SCID_SAT1, SCID_SAT2, lora_airtime_ms)

CAPTURE = os.path.join(HERE, "adv_capture.json")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="the adversary's radio, e.g. COM5")
    ap.add_argument("--sat2", action="store_true", help="SAT-2's channel pair")
    ap.add_argument("--as-ground", action="store_true", help="the ground station's virtual channel")
    ap.add_argument("attack", choices=["record", "replay"])
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--flip", action="store_true", help="replay each frame with one bit changed in the data field")
    ap.add_argument("--gap", type=float, default=0.4, help="pause between replayed frames, seconds")
    a = ap.parse_args()
    up, down = (SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ) if a.sat2 else (UPLINK_MHZ, DOWNLINK_MHZ)

    if a.attack == "record":
        link = SerialLink(a.port, tx_mhz=down, rx_mhz=up)
        print(f"listening on the uplink ({up} MHz) for {a.seconds:.0f} s:",
              "OK" if link.freq_ok else "the radio did not answer the retune")
        frames, end = [], time.time() + a.seconds
        while time.time() < end:
            r = link.recv(0.5)
            if r is not None:
                frames.append(dict(t=round(time.time(), 2), rssi=r[0], frame=r[2].hex()))
        with open(CAPTURE, "w") as f:
            json.dump(frames, f)
        vcs = sorted({(bytes.fromhex(x["frame"])[2] >> 2) & 0x3F for x in frames if len(x["frame"]) >= 14})
        print(f"{len(frames)} uplink frames recorded (virtual channels {vcs}) -> {os.path.basename(CAPTURE)}")
        link.close()
        return 0

    if not os.path.exists(CAPTURE):
        print("no recording found: run 'record' first")
        return 1
    rec = json.load(open(CAPTURE))
    link = SerialLink(a.port, tx_mhz=up, rx_mhz=down)
    sent = []
    for x in rec:
        fr = bytearray(bytes.fromhex(x["frame"]))
        if a.flip and len(fr) > 8:
            fr[len(fr) // 2] ^= 0x01
        link.send(bytes(fr))
        sent.append(bytes(fr))
        time.sleep(a.gap)
    air = round(sum(lora_airtime_ms(len(f)) for f in sent) / 1000, 1)
    out = dict(attack="replay" + ("_flip" if a.flip else ""), time=time.strftime("%Y-%m-%d %H:%M:%S"),
               channel="SAT-2" if a.sat2 else "SAT-1", frames_sent=len(sent), air_time_s=air)
    path = os.path.join(HERE, f"adv_{out['attack']}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print(f"{len(sent)} frames sent again, {air} s of air time -> {os.path.basename(path)}")
    print("read the bridge window for the satellite's reaction (rejected, replay, timed out).")
    link.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

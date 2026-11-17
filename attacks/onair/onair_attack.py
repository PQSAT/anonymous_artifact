#!/usr/bin/env python3
"""On the air adversary, in its own folder, for the attack evidence against the real board.

The adversary is one spare 868 MHz T-Beam. It only listens on the radio and transmits on the
radio. It never opens the Versal console and never writes to the board, so it cannot harm the
Versal. If you point it at the Versal port by mistake it refuses to run.

What it does:
  record   listen on the user channel and save the frames the user sends (run this while a
           normal handshake is happening, so the frames are genuine)
  replay   send the saved frames again at the satellite. The satellite rejects them because
           the timestamp and the nonce are old. This is the replay attack.
  flip     send the saved frames again with one bit changed in each. The satellite rejects
           them on the SDLS tag and the signature. This is the forged and bit flip attack.

Usage (replace COMx with the adversary board, not COM7):
  py onair_attack.py --port COMx record --seconds 180
  py onair_attack.py --port COMx replay
  py onair_attack.py --port COMx flip

The satellite's reaction shows in the bridge window (lines with rejected, replay, failed).
A report is written to onair_report.json in this folder.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
from ccsds_link import SerialLink, UPLINK_MHZ, DOWNLINK_MHZ, SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ, lora_airtime_ms  # noqa: E402

CAPTURE = os.path.join(HERE, "onair_capture.json")
# the Versal console must never be opened by this tool
VERSAL_PORTS = {"COM7"}


def guard(port):
    if port.upper() in VERSAL_PORTS:
        print(f"refusing to use {port}: that is the Versal console. Use the adversary radio board.")
        sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="the adversary radio board (NOT COM7)")
    ap.add_argument("--sat2", action="store_true", help="use SAT-2's channel pair instead of SAT-1's")
    ap.add_argument("action", choices=["record", "replay", "flip"])
    ap.add_argument("--seconds", type=float, default=180, help="record for this long")
    ap.add_argument("--gap", type=float, default=0.4, help="pause between replayed frames")
    a = ap.parse_args()
    guard(a.port)
    up, down = (SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ) if a.sat2 else (UPLINK_MHZ, DOWNLINK_MHZ)

    if a.action == "record":
        # listen on the uplink: the adversary hears what the user transmits
        link = SerialLink(a.port, tx_mhz=down, rx_mhz=up)
        print(f"listening on the user uplink ({up} MHz) for {a.seconds:.0f} s.", flush=True)
        print("start or let a normal handshake run now, so real user frames are captured.", flush=True)
        if link.freq_ok is False:
            print("the board did not answer the tune command. Is modem.ino flashed on this board?")
            return 1
        frames, end = [], time.time() + a.seconds
        while time.time() < end:
            r = link.recv(0.5)
            if r is not None:
                frames.append(dict(t=round(time.time(), 2), rssi=r[0], snr=r[1], frame=r[2].hex()))
                print(f"  captured frame {len(frames)} ({len(r[2])} B, rssi {r[0]})", flush=True)
        with open(CAPTURE, "w") as f:
            json.dump(frames, f)
        link.close()
        print(f"\n{len(frames)} user frames recorded -> onair_capture.json")
        if not frames:
            print("nothing captured. Record again while a handshake is actually running.")
        return 0

    if not os.path.exists(CAPTURE):
        print("no recording found. Run 'record' first, during a handshake.")
        return 1
    rec = json.load(open(CAPTURE))
    if not rec:
        print("the recording is empty. Record again while a handshake is running.")
        return 1
    link = SerialLink(a.port, tx_mhz=up, rx_mhz=down)      # transmit on the uplink at the satellite
    if link.freq_ok is False:
        print("the board did not answer the tune command. Is modem.ino flashed on this board?")
        return 1
    sent = []
    print(f"sending {len(rec)} recorded frames at the satellite ({up} MHz)"
          + (", one bit changed in each" if a.action == "flip" else "") + " ...", flush=True)
    for i, x in enumerate(rec, 1):
        fr = bytearray(bytes.fromhex(x["frame"]))
        if a.action == "flip" and len(fr) > 8:
            fr[len(fr) // 2] ^= 0x01
        link.send(bytes(fr))
        sent.append(bytes(fr))
        print(f"  sent frame {i} of {len(rec)} ({len(fr)} B)", flush=True)
        time.sleep(a.gap)
    link.close()
    air = round(sum(lora_airtime_ms(len(f)) for f in sent) / 1000, 1)
    report = dict(attack="replay_flip" if a.action == "flip" else "replay",
                  when=time.strftime("%Y-%m-%d %H:%M:%S"), channel="SAT-2" if a.sat2 else "SAT-1",
                  frames_sent=len(sent), air_time_s=air)
    path = os.path.join(HERE, "onair_report.json")
    hist = json.load(open(path)) if os.path.exists(path) else []
    hist.append(report)
    with open(path, "w") as f:
        json.dump(hist, f, indent=1)
    print(f"\n{len(sent)} frames sent again, {air} s of air time.")
    print("now read the bridge window: the satellite should log the frames as rejected or replayed,")
    print("and no handshake should complete from them. report -> onair_report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

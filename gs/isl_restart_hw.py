#!/usr/bin/env python3
"""isl_restart_hw.py  restart of the inter satellite association on the bench.

    py isl_restart_hw.py record --gs COM4            before a restart: 10 protected ISL frames, saved
    py isl_restart_hw.py replay --gs COM4            after a restart: send the saved frames again, count

record  sends N forwarded PINGs to SAT-2 through SAT-1.  Each crosses the RF ISL as a protected
        frame.  The frames SAT-1 transmitted are taken from the bridge's ISL log and saved to
        isl_recorded.txt with the IV of each.
replay  asks the running bridge to transmit the saved frames again on SAT-1's ISL radio, then
        counts in SAT-2's log how many were rejected by SDLS and how many forwarded commands
        were executed again.  Then it sends N new PINGs and counts how many of the new frames
        use an IV that a saved frame used.

The bridge must be running in the laptop folder (it writes the logs this script reads).
"""
import argparse
import csv
import datetime
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAPTOP = os.path.join(HERE, "..", "bridge")
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.insert(0, os.path.join(HERE, "..", "protocol"))
from ccsds_link import SerialLink, Terminal, ADDR_GS, TC_VC_GROUND, SCID_SAT2, CMD_PING, CMD_SET_TIME  # noqa: E402

ISL_LOG = os.path.join(LAPTOP, "sat1_bridge_log_isl.csv")
SAT2_LOG = os.path.join(LAPTOP, "sat1_bridge_log_sat2.csv")
SAVED = os.path.join(HERE, "isl_recorded.txt")


def iv_of(hx):
    return hx[16:40]                      # TM primary header 6 | SPI 2 | IV 12 (salt 4, counter 8)


def isl_frames_since(t0):
    """Frames SAT-1 transmitted on the ISL since t0 (ISO time), from the bridge log."""
    out = []
    with open(ISL_LOG, newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 12 and row[0] >= t0 and row[1] == "isl_tx" and row[2] == "1" and row[10].startswith("ok"):
                out.append(row[11].upper())
    return out


def sat2_lines_since(t0):
    out = []
    with open(SAT2_LOG, newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 6 and row[0] >= t0 and row[1] == "sat":
                out.append(row[5])
    return out


def ground(port):
    gs = Terminal(SerialLink(port), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
    gs.wait(15)
    print("COP-1:", "OK" if gs.init_cop() else "FAILED", " clock:", gs.set_time())
    gs.forward_command(SCID_SAT2, CMD_SET_TIME, struct.pack(">I", int(time.time())), wait_ack=8.0)
    return gs


def pings(gs, n):
    t0 = datetime.datetime.now().isoformat(timespec="milliseconds")
    ok = sum(gs.forward_command(SCID_SAT2, CMD_PING, wait_ack=12.0) == "OK" for _ in range(n))
    time.sleep(4)
    return ok, t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["record", "replay"])
    ap.add_argument("--gs", required=True, help="ground station radio, e.g. COM4")
    ap.add_argument("--n", type=int, default=10)
    a = ap.parse_args()
    if not os.path.exists(ISL_LOG):
        print("no ISL log in the laptop folder: is the bridge running with the four --isl ports?")
        return 1
    gs = ground(a.gs)
    if a.what == "record":
        ok, t0 = pings(gs, a.n)
        frames = isl_frames_since(t0)
        with open(SAVED, "w") as f:
            f.write("\n".join(frames) + "\n")
        print(f"{ok} of {a.n} forwarded commands executed, {len(frames)} ISL frames of SAT-1 saved to isl_recorded.txt")
        if frames:
            print(f"salt {frames[0][16:24]}, frame counters {int(frames[0][24:40], 16)} to {int(frames[-1][24:40], 16)}")
    else:
        if not os.path.exists(SAVED):
            print("isl_recorded.txt not found: run record before the restart")
            return 1
        saved = [l.strip() for l in open(SAVED) if l.strip()]
        t0 = datetime.datetime.now().isoformat(timespec="milliseconds")
        with open(os.path.join(LAPTOP, "isl_replay.txt"), "w") as f:
            f.write("\n".join(saved) + "\n")
        wait_s = 35 + 2.2 * len(saved)
        print(f"{len(saved)} saved frames handed to the bridge, waiting {wait_s:.0f} s", flush=True)
        time.sleep(wait_s)
        lines = sat2_lines_since(t0)
        rej = sum("rejected by SDLS" in l for l in lines)
        exe = sum("forwarded command" in l and "executed" in l for l in lines)
        print(f"frames recorded before the restart and sent again: {len(saved)}")
        print(f"   rejected by SDLS at SAT-2: {rej}")
        print(f"   forwarded commands executed again at SAT-2: {exe}")
        ok, t1 = pings(gs, a.n)
        new = isl_frames_since(t1)
        reused = len({iv_of(h) for h in saved} & {iv_of(h) for h in new})
        print(f"new traffic: {ok} of {a.n} forwarded commands executed, {len(new)} ISL frames")
        if new:
            print(f"   salt {new[0][16:24]}, first frame counter {int(new[0][24:40], 16)}")
        print(f"   IVs of the saved frames used again by the new frames: {reused}")
    gs.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

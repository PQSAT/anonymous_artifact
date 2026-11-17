"""Clear stale link protection on the satellite.

After a completed handshake the satellite protects the user link and the ground link with
SDLS keyed from that session key.  A terminal program that is started again has no key: the
satellite drops its clear frames and the terminal cannot read the protected downlink, so every
new handshake fails with "timeout waiting for MSG2".

This tool takes the session key of the last completed handshake from its result file, sends
the Stop SA command (CCSDS 355.1) under that key and checks that the link is in clear again.

    python sa_recover.py --gs COM4                         newest result file in this folder
    python sa_recover.py --gs COM4 --json auth_hw_ref_20261114_144613.json
"""
import argparse
import glob
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
from ccsds_link import Terminal, ADDR_GS, TC_VC_GROUND, CMD_SA_STOP, CMD_PING  # noqa: E402


def last_session_key(path=None):
    """Session key of the newest completed handshake, from one file or from every result file here."""
    files = [path] if path else sorted(glob.glob(os.path.join(HERE, "auth_hw_*.json")), key=os.path.getmtime)
    best = None
    for f in files:
        try:
            runs = json.load(open(f))
        except (OSError, ValueError):
            continue
        for r in runs if isinstance(runs, list) else [runs]:
            if r.get("ok") and r.get("sk_ground"):
                best = (f, bytes.fromhex(r["sk_ground"]))
    return best


def link_is_clear(gs):
    """True when a command sent in clear comes back acknowledged."""
    gs.sdls_stop()
    return any(gs.command(CMD_PING)==chr(79)+chr(75) for _ in range(3)) or gs.command(CMD_PING) == "OK"


def recover(gs, sk, tries=6):
    """Send Stop SA under sk until the satellite answers in clear.  Returns True on success."""
    if link_is_clear(gs):
        print("the link is already in clear, nothing to do")
        return True
    # The satellite ignores a protected frame whose number it has already seen, and every
    # attempt here starts counting again.  So one attempt has to send more frames than the
    # ground station sent under this key before (a hand over run sends about a dozen).
    burst = [4, 16, 32, 48, 64, 96]
    for i in range(tries):
        gs.sdls_start(sk)
        print(f"attempt {i + 1}: sending {burst[min(i, len(burst) - 1)]} protected Stop SA frames")
        for _ in range(burst[min(i, len(burst) - 1)]):
            gs.command(CMD_SA_STOP, wait_ack=1.0)
        time.sleep(1.0)
        if link_is_clear(gs):
            print(f"security associations stopped after attempt {i + 1}: the link is in clear")
            return True
        print(f"attempt {i + 1}: still protected")
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gs", required=True, help="ground station radio, e.g. COM4")
    ap.add_argument("--json", help="result file of the last completed handshake")
    a = ap.parse_args()
    from ccsds_link import SerialLink
    found = last_session_key(a.json)
    if found is None:
        print("no completed handshake with a session key found in the result files")
        sys.exit(1)
    print("session key taken from", os.path.basename(found[0]))
    gs = Terminal(SerialLink(a.gs), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False, show_relay=False).start()
    print("waiting for SAT-1 housekeeping ...")
    gs.wait(30)
    if gs.hk is None:
        print("no housekeeping. check the bridge.")
        sys.exit(1)
    print("COP-1:", "OK" if gs.init_cop() else "FAILED")
    ok = recover(gs, found[1])
    print("RESULT:", "LINK IN CLEAR, start the handshakes" if ok else "FAILED, the satellite needs a restart")
    gs._run = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""send_crl.py  build a revocation list, sign it as the trusted authority and distribute it.

    python send_crl.py --revoke 0x0011                       write crl.bin only
    python send_crl.py --revoke 0x0011 --port COM4           and uplink it to SAT-1
    python send_crl.py --revoke 0x0011 --port COM4 --sat 0x102    to SAT-2, through SAT-1 and the ISL
    python send_crl.py --revoke none --port COM4             an empty list (reinstates everyone)

The list is the protocol message of type 0x0A: issue time, the revoked identities and the
authority's ML-DSA-65 signature.  A satellite installs it only if that signature verifies
and the list is newer than the one it holds, so it can travel over any link.  crl.bin can
also be put in the satellite's auth folder on the SD card; it is read at start.
Needs protocol/keys/ta.json (the authority's signing key): run this where the authority is kept.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.insert(0, os.path.join(HERE, "..", "protocol"))
import pqsat_proto as P  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--revoke", required=True, help="comma separated identities, e.g. 0x0011,0x0103, or none")
    ap.add_argument("--keys", default=os.path.join(HERE, "..", "protocol", "keys"))
    ap.add_argument("--out", default="crl.bin")
    ap.add_argument("--port", help="ground station radio; when given the list is uplinked")
    ap.add_argument("--sat", default="0x101", help="satellite to address (default SAT-1)")
    a = ap.parse_args()
    idents = [] if a.revoke.lower() == "none" else [int(x, 0) for x in a.revoke.split(",")]
    ta = json.load(open(os.path.join(a.keys, "ta.json")))
    crl = P.enc_crl(bytes.fromhex(ta["sk_sigma"]), idents)
    issued, check = P.dec_crl(crl, bytes.fromhex(ta["pk_sigma"]))
    with open(a.out, "wb") as f:
        f.write(crl)
    print(f"revocation list: {len(idents)} identities {[hex(i) for i in sorted(check)]}, issued {issued}, "
          f"{len(crl)} octets, written to {a.out}")
    if not a.port:
        return 0
    from ccsds_link import SerialLink, Terminal, ADDR_GS, TC_VC_GROUND
    t = Terminal(SerialLink(a.port), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False, show_relay=False).start()
    t.wait(15)
    if not t.init_cop():
        print("COP-1 did not initialise: is the bridge running and the satellite in range?")
        return 1
    t0 = time.time()
    ok = t.send_auth(int(a.sat, 0), crl)
    print(f"uplink to SAT {int(a.sat, 0):04X}: {'every segment acknowledged' if ok else 'FAILED'} in {time.time() - t0:.1f} s")
    print("expect on the bridge:  auth: revocation list installed, N revoked, issued ...")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

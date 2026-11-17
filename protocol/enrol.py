#!/usr/bin/env python3
"""Enrollment tool: Phases 1 to 4, run once, offline.

Creates the trusted authority, enrols Satellite 1, the ground station and User 1,
and writes each entity's provisioning bundle.

    python3 enrol.py --out keys/

Files written:
    ta.json                 the authority's public keys (and private keys; keep offline)
    sat1.bundle             satellite bundle in the layout sat_auth.c loads
    gs.cert                 ground station certificate bundle, loaded by the satellite
    gs.pickle, ue1.pickle   Python bundles for the ground station and the user terminal
    sat1.cert, ue1.cert     certificate bundles, for pre loading peers
"""
import argparse
import json
import os
import pickle
import struct

import pqsat_proto as P

ID_GS, ID_UE1, ID_SAT1, ID_SAT2 = 0x0001, 0x0011, 0x0101, 0x0102


def load_ta(path):
    """Rebuild the authority from ta.json so further entities join the same trust domain."""
    with open(path) as f:
        d = json.load(f)
    ta = P.TrustedAuthority.__new__(P.TrustedAuthority)
    ta.pk_sigma, ta.sk_sigma = bytes.fromhex(d["pk_sigma"]), bytes.fromhex(d["sk_sigma"])
    ta.pk_kappa, ta.sk_kappa = bytes.fromhex(d["pk_kappa"]), bytes.fromhex(d["sk_kappa"])
    ta.master_key = bytes.fromhex(d["master_key"])
    return ta


def add_satellite(out, name, ident, validity_days):
    """Enrol one more satellite under the existing authority (Phase 2 for a new node).
    Writes name.bundle, name.cert and name.pickle; nothing already issued changes."""
    ta = load_ta(os.path.join(out, "ta.json"))
    b = ta.enrol(ident, P.ROLE_SAT, validity_days)
    write_sat_bundle(os.path.join(out, name + ".bundle"), b, ID_GS)
    with open(os.path.join(out, name + ".cert"), "wb") as f:
        f.write(b["cert"].bundle())
    with open(os.path.join(out, name + ".pickle"), "wb") as f:
        pickle.dump(b, f)
    c = b["cert"]
    print(f"{name:6s} id {c.ident:#06x}  cert {len(c.bundle())} B  digest {c.digest().hex()[:16]}...  "
          f"self check {c.verify(ta.pk_sigma, b['sk_kappa'])}  (added under the existing authority)")


def write_sat_bundle(path, b, id_gs):
    """ident 2 | id_gs 2 | sk_sigma | sk_kappa | ta_pk_sigma | own certificate bundle"""
    with open(path, "wb") as f:
        f.write(struct.pack(">HH", b["ident"], id_gs))
        f.write(b["sk_sigma"])
        f.write(b["sk_kappa"])
        f.write(b["ta_pk_sigma"])
        f.write(b["cert"].bundle())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="keys")
    ap.add_argument("--validity-days", type=int, default=365)
    ap.add_argument("--add-sat", metavar="NAME:ID", help="enrol one more satellite, e.g. sat2:0x0102, keeping ta.json")
    ap.add_argument("--isl", metavar="A:B", help="write the pairwise inter satellite link key isl_A_B.key (32 random "
                                                "octets, loaded by both satellites at provisioning)")
    a = ap.parse_args()
    if a.isl:
        x, y = a.isl.split(":")
        path = os.path.join(a.out, f"isl_{x}_{y}.key")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        print("ISL key written to", path)
    if a.add_sat:
        name, ident = a.add_sat.split(":")
        add_satellite(a.out, name, int(ident, 0), a.validity_days)
    if a.isl or a.add_sat:
        return
    os.makedirs(a.out, exist_ok=True)

    ta = P.TrustedAuthority()
    sat = ta.enrol(ID_SAT1, P.ROLE_SAT, a.validity_days)
    gs = ta.enrol(ID_GS, P.ROLE_GS, a.validity_days)
    ue = ta.enrol(ID_UE1, P.ROLE_UE, a.validity_days)

    with open(os.path.join(a.out, "ta.json"), "w") as f:
        json.dump(dict(pk_sigma=ta.pk_sigma.hex(), pk_kappa=ta.pk_kappa.hex(),
                       sk_sigma=ta.sk_sigma.hex(), sk_kappa=ta.sk_kappa.hex(),
                       master_key=ta.master_key.hex()), f, indent=1)

    write_sat_bundle(os.path.join(a.out, "sat1.bundle"), sat, ID_GS)
    for name, b in (("sat1", sat), ("gs", gs), ("ue1", ue)):
        with open(os.path.join(a.out, name + ".cert"), "wb") as f:
            f.write(b["cert"].bundle())
    for name, b in (("gs", gs), ("ue1", ue), ("sat1", sat)):
        with open(os.path.join(a.out, name + ".pickle"), "wb") as f:
            pickle.dump(b, f)

    for name, b in (("SAT-1", sat), ("GS", gs), ("UE1", ue)):
        c = b["cert"]
        print(f"{name:6s} id {c.ident:#06x}  cert {len(c.bundle())} B  digest {c.digest().hex()[:16]}...  "
              f"self check {c.verify(ta.pk_sigma, b['sk_kappa'])}")
    print("written to", a.out)


if __name__ == "__main__":
    main()

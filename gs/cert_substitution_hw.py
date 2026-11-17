#!/usr/bin/env python3
"""cert_substitution_hw.py  certificate substitution against the satellite on the bench.

    py cert_substitution_hw.py --gs COM4 --ue COM8
    py cert_substitution_hw.py --gs COM4 --ue COM8 --norule      board started with the word norule

The adversary transmits on the ground station radio in the place of the ground station.  It
holds no long term ML-KEM secret key of any party.  It uses one forged signature of the
authority on a certificate that binds its own keys to the identity of the ground station
(made here with the authority's key in protocol/keys/ta.json, which stands for a broken ML-DSA).

User and ground station are both on SAT-1 (one satellite path).  Start the board, start the
bridge, then run this.  With the certificate rule on the board both attempts must stop after
MSG3 and the honest handshake afterwards must complete.  With --norule (board started without
the rule) attempt 2 is expected to complete with the adversary holding the session key; power
cycle the board after that run.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.insert(0, os.path.join(HERE, "..", "protocol"))
from ccsds_link import SerialLink, Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, UPLINK_MHZ, DOWNLINK_MHZ  # noqa: E402
import pqsat_proto as P                                                             # noqa: E402
from pqsat_roles import UserSession, GroundSession, HandshakeFailed                 # noqa: E402
from handshake_runner import run_handshake, load_bundle, KEYS                       # noqa: E402
import auth_campaign                                                                # noqa: E402

ID_GS, ID_UE, ID_SAT = 0x0001, 0x0011, 0x0101


class Rogue(GroundSession):
    """The adversary in the ground station's place.  It does not check what it cannot check."""
    def _verify(self, name, pk, ss, digest, hsig, require_kem=True):
        return


def wait(term, types, timeout):
    end = time.time() + timeout
    while time.time() < end:
        r = term.wait_auth(min(5.0, max(0.1, end - time.time())))
        if r is not None and r[1][1] in types:
            return r[1]
    raise HandshakeFailed(f"nothing from the satellite within {timeout:.0f} s")


def send(term, msg):
    if not term.send_auth(ID_SAT, msg):
        raise HandshakeFailed("uplink not acknowledged")


def attempt(ue_term, gs_term, ue, adv, step_timeout):
    for t in (ue_term, gs_term):
        t.auth_rx.clear()
    ue.state, ue.sk = "idle", None
    step = "MSG1"
    try:
        print("   MSG1 up (user)", flush=True)
        send(ue_term, ue.start(ID_SAT, ID_GS)[0][1])
        step = "MSG2"
        out = adv.handle(wait(gs_term, (P.MSG2,), 600))
        step = "MSG3"
        print("   MSG3 up (adversary, forged certificate in full)", flush=True)
        send(gs_term, out[0][1])
        step = "MSG4"
        print(f"   waiting up to {step_timeout:.0f} s for MSG4", flush=True)
        out = ue.handle(wait(ue_term, (P.MSG4,), step_timeout))
        step = "MSG5"
        send(ue_term, out[0][1])
        step = "MSG6"
        out = adv.handle(wait(gs_term, (P.MSG6,), step_timeout))
        step = "MSG7"
        send(gs_term, out[0][1])
        out = ue.handle(wait(ue_term, (P.MSG7_FWD,), step_timeout))
        step = "MSG8"
        send(ue_term, out[0][1])
        adv.handle(wait(gs_term, (P.MSG8_FWD,), step_timeout))
        return "done", None
    except HandshakeFailed as e:
        return step, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gs", required=True, help="ground station radio, e.g. COM4")
    ap.add_argument("--ue", required=True, help="user radio, e.g. COM8")
    ap.add_argument("--norule", action="store_true", help="the board runs without the certificate rule")
    ap.add_argument("--step-timeout", type=float, default=300.0)
    a = ap.parse_args()

    tap = os.path.join(KEYS, "ta.json")
    if not os.path.exists(tap):
        print("protocol/keys/ta.json not found: run this on the laptop that holds the authority's key")
        return 1
    tj = json.load(open(tap))
    ta = object.__new__(P.TrustedAuthority)
    for k in ("pk_sigma", "sk_sigma", "pk_kappa", "sk_kappa", "master_key"):
        setattr(ta, k, bytes.fromhex(tj[k]))
    b_ue, b_gs, b_sat = load_bundle("ue1"), load_bundle("gs"), load_bundle("sat1")
    forged = ta.enrol(ID_GS, P.ROLE_GS)

    gs = Terminal(SerialLink(a.gs), ADDR_GS, TC_VC_GROUND, name="GS", log_path="gs_certsub_log.csv", show_hk=False).start()
    ue = Terminal(SerialLink(a.ue, tx_mhz=UPLINK_MHZ, rx_mhz=DOWNLINK_MHZ), ADDR_USER1, TC_VC_USER1, name="USER1",
                  log_path="ue_certsub_log.csv", show_hk=False, show_relay=False).start()
    gs.wait(15)
    if not auth_campaign.clear_link(gs):
        print("the ground link does not answer in clear: power cycle the board and start again")
        return 1
    print("COP-1: ground", "OK" if gs.init_cop() else "FAILED", "user", "OK" if ue.init_cop() else "FAILED")
    print("clock:", gs.set_time())

    user = UserSession(b_ue, full_certs=False)
    user.pin_installed = not a.norule
    user.install_cert(b_sat["cert"])
    user.install_cert(b_gs["cert"])
    rec = dict(started=time.strftime("%Y-%m-%d %H:%M:%S"), rule_on_board=not a.norule, attempts=[])
    for n in (1, 2):
        print(f"\n--- attempt {n} ---", flush=True)
        adv = Rogue(forged, full_certs=True)
        adv.cache[ID_SAT], adv.cache[ID_UE] = b_sat["cert"], b_ue["cert"]
        t0 = time.time()
        step, err = attempt(ue, gs, user, adv, a.step_timeout)
        took = user.sk is not None and adv.sk is not None and user.sk == adv.sk
        forged_held = user.cache[ID_GS].digest() == forged["cert"].digest()
        print(f"   attempt {n}: reached {step}{'' if err is None else ', stopped: ' + err}  ({time.time() - t0:.0f} s)")
        print(f"   adversary holds the session key of the user: {took}; user holds the forged certificate: {forged_held}")
        rec["attempts"].append(dict(n=n, reached=step, error=err, seconds=round(time.time() - t0, 1), adversary_has_sk=took,
                                    user_holds_forged=forged_held))
        if took:
            break
        gs.init_cop(); ue.init_cop()
    if not a.norule:
        print("\n--- honest handshake by reference to the installed certificate ---", flush=True)
        try:
            r = run_handshake(ue, gs, mode="ref", preload=True, verbose=True, sdls=True)
            rec["honest_after"] = dict(ok=bool(r["ok"]), seconds=r["seconds"], octets=r["octets_total"])
            print(f"   honest handshake: {'completed' if r['ok'] else 'FAILED'} in {r['seconds']} s, {r['octets_total']} octets")
        except HandshakeFailed as e:
            rec["honest_after"] = dict(ok=False, error=str(e))
            print("   honest handshake FAILED:", e)
    out = time.strftime("cert_substitution_hw_%Y%m%d_%H%M%S.json")
    json.dump(rec, open(out, "w"), indent=1)
    print("\nwritten", out)
    print("now count the satellite's own lines in the bridge log (laptop folder):")
    print('   findstr /c:"differs from the installed one" sat1_bridge_log.csv')
    gs.close(); ue.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

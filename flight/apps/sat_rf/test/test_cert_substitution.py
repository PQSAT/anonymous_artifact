"""Certificate substitution against the flight authentication code, with and without the
certificate policy, on the emulated link.

Adversary: holds NO long term ML-KEM secret key of the user, the satellite or the ground
station.  It can forge one ML-DSA signature of the trusted authority on a certificate (this is
what "ML-DSA broken" means; the forgery is modelled by calling the authority's signing step with
the adversary's own key pairs).  It transmits on the ground link in the place of the ground
station.

    user ---- SAT-1 (flight core and authentication module, C) ---- adversary / ground station

  A. flight code built WITHOUT the policy (-DAUTH_NO_CERT_PIN), terminals without it:
       attempt 1 fails, but the satellite and the user stored the forged certificate
       attempt 2 completes with the adversary in the place of the ground station
  B. flight code WITH the policy (the default build), terminals with it:
       both attempts are rejected at MSG3, the installed certificate is unchanged and
       an honest handshake by reference to the installed certificate still completes

    python3 test_cert_substitution.py        (SF=7 uses the short air time, the radio setting does not matter here)
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "gs"))
sys.path.insert(0, os.path.join(REL, "protocol"))
SF = int(os.environ.get("SF", "7"))
import ccsds_link                                                                   # noqa: E402
ccsds_link.lora_airtime_ms.__defaults__ = (SF, 125e3, 3, 8)
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, lora_airtime_ms  # noqa: E402
from sim_link import SimSatellite, SimModem                                         # noqa: E402
import pqsat_proto as P                                                             # noqa: E402
from pqsat_roles import UserSession, GroundSession, HandshakeFailed                 # noqa: E402
from handshake_runner import run_handshake, load_bundle                             # noqa: E402

KEYS = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_DIR"] = KEYS
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
ID_GS, ID_UE, ID_SAT = 0x0001, 0x0011, 0x0101
STEP = float(os.environ.get("STEP_TIMEOUT", "150"))
results, record = [], {}


def check(name, cond, note=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{note}]" if note else ""), flush=True)


# the authority, as the adversary uses it once: one forged signature over its own keys
_ta = json.load(open(os.path.join(KEYS, "ta.json")))
ta = object.__new__(P.TrustedAuthority)
for k in ("pk_sigma", "sk_sigma", "pk_kappa", "sk_kappa", "master_key"):
    setattr(ta, k, bytes.fromhex(_ta[k]))
b_ue, b_gs, b_sat = load_bundle("ue1"), load_bundle("gs"), load_bundle("sat1")
forged = ta.enrol(ID_GS, P.ROLE_GS)
assert forged["cert"].pk_kappa != b_gs["cert"].pk_kappa and forged["cert"].digest() != b_gs["cert"].digest()


class Rogue(GroundSession):
    """The adversary in the ground station's place.  It does not check what it cannot check."""
    def _verify(self, name, pk, ss, digest, hsig, require_kem=True):
        return


def up(binary):
    env = dict(SAT_NO_SDLS="1", SAT_RX_WINDOW_MS=str(int(lora_airtime_ms(255)) + 800), SAT_LORA_SF=str(SF))
    sat = SimSatellite(os.path.join(HERE, binary), debug=False, env=env, name="SAT-1")
    gs = Terminal(SimModem(sat, "GS"), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
    ue = Terminal(SimModem(sat, "USER1"), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False, show_relay=False).start()
    end = time.time() + 25
    while (gs.hk is None or ue.hk is None) and time.time() < end:
        time.sleep(0.2)
    ok = gs.hk is not None and ue.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK"
    return sat, gs, ue, ok


def down(*things):
    for t in things:
        try:
            t.close()
        except Exception:
            pass


def wait(term, types, timeout):
    end = time.time() + timeout
    while time.time() < end:
        r = term.wait_auth(min(5.0, max(0.1, end - time.time())))
        if r is not None and r[1][1] in types:
            return r[1]
    raise HandshakeFailed("no " + "/".join(f"{t:#04x}" for t in types) + f" from the satellite within {timeout:.0f} s")


def send(term, msg):
    if not term.send_auth(ID_SAT, msg):
        raise HandshakeFailed("uplink not acknowledged")


def attempt(ue_term, gs_term, ue, gs):
    """One handshake with the given ground role (the adversary).  Returns the step reached."""
    for t in (ue_term, gs_term):
        t.auth_rx.clear()
    ue.state, ue.sk = "idle", None
    step = "MSG1"
    try:
        send(ue_term, ue.start(ID_SAT, ID_GS)[0][1])
        step = "MSG2"
        out = gs.handle(wait(gs_term, (P.MSG2,), STEP))
        step = "MSG3"
        send(gs_term, out[0][1])                       # MSG3 with the forged certificate in full
        step = "MSG4"
        out = ue.handle(wait(ue_term, (P.MSG4,), STEP))
        step = "MSG5"
        send(ue_term, out[0][1])
        step = "MSG6"
        out = gs.handle(wait(gs_term, (P.MSG6,), STEP))
        step = "MSG7"
        send(gs_term, out[0][1])
        out = ue.handle(wait(ue_term, (P.MSG7_FWD,), STEP))
        step = "MSG8"
        send(ue_term, out[0][1])
        gs.handle(wait(gs_term, (P.MSG8_FWD,), STEP))
        step = "done"
        return step, None
    except HandshakeFailed as e:
        return step, str(e)


def sessions(pin):
    ue = UserSession(b_ue, full_certs=False)
    ue.pin_installed = pin
    ue.install_cert(b_sat["cert"])
    ue.install_cert(b_gs["cert"])                      # the genuine ground station certificate, installed at enrollment
    return ue


def rogue():
    r = Rogue(forged, full_certs=True)
    r.cache[ID_SAT], r.cache[ID_UE] = b_sat["cert"], b_ue["cert"]   # public certificates
    return r


def has(sat, mark, text):
    return any(text in l for l in sat.log[mark:])


def variant(label, binary, pin):
    print(f"\n=== {label}: satellite {binary}, terminals {'with' if pin else 'without'} the policy ===")
    sat, gs_term, ue_term, ok = up(binary)
    check("satellite up, COP-1 and clock", ok)
    ue = sessions(pin)
    out = dict(binary=binary, policy=pin, attempts=[])
    for n in (1, 2):
        mark = len(sat.log)
        adv = rogue()
        t0 = time.time()
        step, err = attempt(ue_term, gs_term, ue, adv)
        dt = time.time() - t0
        took = ue.sk is not None and adv.sk is not None and ue.sk == adv.sk
        sat_done = has(sat, mark, "auth: handshake complete")
        sat_pin = has(sat, mark, "differs from the installed one")
        sat_rej = has(sat, mark, "ground station certificate rejected")
        user_holds_forged = ue.cache[ID_GS].digest() == forged["cert"].digest()
        print(f"   attempt {n}: reached {step}{'' if err is None else ', stopped: ' + err}  ({dt:.0f} s)")
        print(f"      adversary holds the session key of the user: {took}; satellite completed: {sat_done}; "
              f"satellite rejected the certificate at MSG3: {sat_pin and sat_rej}; user holds the forged certificate: {user_holds_forged}")
        out["attempts"].append(dict(n=n, reached=step, error=err, seconds=round(dt, 1), adversary_has_sk=took, satellite_completed=sat_done,
                                    satellite_rejected_at_msg3=bool(sat_pin and sat_rej), user_holds_forged=user_holds_forged,
                                    satellite_lines=[l for l in sat.log[mark:] if l.startswith("auth:")][-8:]))
    a1, a2 = out["attempts"]
    if not pin:
        check("A. attempt 1 does not complete", a1["reached"] != "done" and not a1["adversary_has_sk"], a1["reached"])
        check("A. attempt 2 completes with the adversary in the place of the ground station", a2["reached"] == "done" and a2["adversary_has_sk"] and a2["satellite_completed"])
    else:
        check("B. attempt 1 rejected by the satellite at MSG3", a1["satellite_rejected_at_msg3"] and not a1["adversary_has_sk"], a1["reached"])
        check("B. attempt 2 rejected by the satellite at MSG3", a2["satellite_rejected_at_msg3"] and not a2["adversary_has_sk"], a2["reached"])
        check("B. the satellite completed no handshake with the adversary", not a1["satellite_completed"] and not a2["satellite_completed"])
        check("B. the user still holds the genuine certificate", not a2["user_holds_forged"])
        mark = len(sat.log)
        r = run_handshake(ue_term, gs_term, mode="ref", preload=True, verbose=False, sdls=False)
        out["honest_after"] = dict(ok=bool(r["ok"]), seconds=r["seconds"], octets=r["octets_total"])
        check("B. honest handshake by reference to the installed certificate completes afterwards", r["ok"] and has(sat, mark, "auth: handshake complete"),
              f"{r['seconds']} s, {r['octets_total']} octets")
        check("B. the satellite asked for no certificate and rejected none in the honest handshake",
              not has(sat, mark, "differs from the installed one") and not has(sat, mark, "certificate rejected"))
    record[label] = out
    down(gs_term, ue_term, sat)


which = os.environ.get("ONLY", "AB")
if "A" in which:
    variant("A", "satsim_nopin", False)
if "B" in which:
    variant("B", "satsim", True)
json.dump(record, open(os.path.join(HERE, "cert_substitution.json"), "w"), indent=1)
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

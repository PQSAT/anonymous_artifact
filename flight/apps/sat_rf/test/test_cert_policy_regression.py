"""The certificate policy does not break honest handshakes (emulated link, flight code with the policy).

  1. full certificate mode, peers' certificates installed: the certificates received in band
     are the installed ones and are accepted
  2. the satellite has no certificate of the user installed: the user sends its certificate in
     full, the satellite takes it as a candidate for that handshake and the handshake completes
     (first contact)
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
SF = int(os.environ.get("SF", "7"))
import ccsds_link                                                                   # noqa: E402
ccsds_link.lora_airtime_ms.__defaults__ = (SF, 125e3, 3, 8)
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, lora_airtime_ms  # noqa: E402
from sim_link import SimSatellite, SimModem                                         # noqa: E402
from handshake_runner import run_handshake                                          # noqa: E402

KEYS = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_DIR"] = KEYS
results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{note}]" if note else ""), flush=True)


def run(label, env_extra, mode, preload):
    for k in ("SAT_AUTH_REF", "SAT_AUTH_PRELOAD_UE"):
        os.environ.pop(k, None)
    os.environ.update(env_extra)
    env = dict(SAT_NO_SDLS="1", SAT_RX_WINDOW_MS=str(int(lora_airtime_ms(255)) + 800), SAT_LORA_SF=str(SF))
    sat = SimSatellite(os.path.join(HERE, "satsim"), debug=False, env=env, name="SAT-1")
    gs = Terminal(SimModem(sat, "GS"), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
    ue = Terminal(SimModem(sat, "USER1"), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False, show_relay=False).start()
    end = time.time() + 25
    while (gs.hk is None or ue.hk is None) and time.time() < end:
        time.sleep(0.2)
    check(label + ": satellite up", gs.init_cop() and ue.init_cop() and gs.set_time() == "OK")
    r = run_handshake(ue, gs, mode=mode, preload=preload, verbose=False, sdls=False)
    check(label + ": handshake completes", r["ok"] and any("auth: handshake complete" in l for l in sat.log), f"{r['seconds']} s, {r['octets_total']} octets")
    check(label + ": no certificate rejected", not any("differs from the installed one" in l or "certificate rejected" in l for l in sat.log))
    for t in (gs, ue, sat):
        t.close()
    return sat.log


if os.environ.get("ONLY", "12").find("1") >= 0:
    run("1. full mode, certificates installed", dict(SAT_AUTH_PRELOAD_UE="1"), "full", True)
log = run("2. first contact, user certificate not installed at the satellite", dict(SAT_AUTH_REF="1"), "full", True)
check("2. the candidate certificate was kept, the handshake having completed", not any("candidate certificate" in l for l in log))
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

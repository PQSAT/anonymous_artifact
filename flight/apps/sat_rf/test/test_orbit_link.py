"""Orbit conditions and automatic clearing of stale link protection, on the emulated link.

1. a handshake on the clean link, then a restarted ground terminal without the key: the
   campaign's clear_link finds the link protected, stops the associations with the ground
   link key and the link answers in clear
2. a handshake under the conditions of the highest pass of the PQSAT-8 model, started in
   the usable part of the pass: the model's delay and loss are applied and counted
3. the model at rise of the same pass removes nearly every frame (margin below zero at SF9)
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "gs"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, CMD_PING  # noqa: E402
from sim_link import SimSatellite, SimModem                                                  # noqa: E402
from handshake_runner import run_handshake                                                   # noqa: E402
from pqsat_roles import HandshakeFailed                                                      # noqa: E402
from orbit_link import PassModel, ModelledLink                                               # noqa: E402
import auth_campaign                                                                         # noqa: E402

os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{note}]" if note else ""), flush=True)


m_gs, m_ue = PassModel(site="ground", choose="high", seed=1), PassModel(site="user", choose="high", seed=2)
info = m_ue.describe()
print("pass:", info)
sat = SimSatellite(os.path.join(HERE, "satsim"), debug=False)
gs = Terminal(ModelledLink(SimModem(sat, "GS"), m_gs), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
ue = Terminal(ModelledLink(SimModem(sat, "USER1"), m_ue), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False, show_relay=False).start()
end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("housekeeping, COP-1 and clock", gs.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK")

print("\n--- 1. clean link, then a ground terminal that lost its key ---")
r = run_handshake(ue, gs, mode="ref", preload=True)
check("handshake on the clean link", r["ok"], f"{r['seconds']} s")
check("the model touched no frame while it was off", m_ue.stats["sent"] == 0 and m_gs.stats["received"] == 0)
key = bytes.fromhex(r["sk_ground"])
gs.sdls_stop(); ue.sdls_stop()
check("without the key the satellite does not answer a clear command", gs.command(CMD_PING) != "OK")
check("clear_link stops the stale associations with the ground link key", auth_campaign.clear_link(gs, key))
check("a clear command is acknowledged again", gs.command(CMD_PING) == "OK")
gs.init_cop(); ue.init_cop()

print("\n--- 2. handshake under the conditions of the highest pass ---")
off = info["usable_from_s"]
for m in (m_gs, m_ue):
    m.start(off)
try:
    r = run_handshake(ue, gs, mode="ref", preload=True)
except HandshakeFailed as e:
    r = dict(ok=False, error=str(e), seconds=None)
endt = m_ue.tau()
st = m_ue.stats
print(f"   started {off} s after rise, ended {endt:.0f} s after rise, pass {info['pass_seconds']} s, usable {info['usable_seconds']} s")
print(f"   user link: {st['sent_removed']} of {st['sent']} sent removed, {st['received_removed']} of {st['received']} received removed")
print(f"   ground link: {m_gs.stats}")
print(f"   outcome: {'completed in ' + str(r['seconds']) + ' s' if r['ok'] else 'not completed: ' + r['error']}")
check("the model was applied to the frames of both links", st["sent"] > 20 and st["received"] > 20 and m_gs.stats["sent"] > 20)
check("the delay follows the slant range (4 to 12 ms one way)", all(4.0 < s["delay_ms"] < 12.5 for s in m_ue.trace) and len(m_ue.trace) > 3)
check("the outcome is recorded either way (completed, or not completed with the reason)", r["ok"] or bool(r.get("error")))
for m in (m_gs, m_ue):
    m.stop()

print("\n--- 3. the model at rise ---")
m = PassModel(site="user", choose="high", seed=3).start(0.0)
kept = sum(1 for _ in range(500) if m.passes_frame("up")[0])
check("at rise (margin below zero at SF9) nearly every frame is removed", kept < 10, f"{kept} of 500 kept, margin {m.state()['margin_db']} dB")
m.start(-5.0)
check("before rise no frame passes", not m.passes_frame("up")[0] and m.stats["outside_window"] == 1)

sat.close()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

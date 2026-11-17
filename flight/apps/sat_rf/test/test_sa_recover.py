"""A terminal program that is restarted after a completed handshake: reproduce the failure
seen on hardware on 14 November and check that sa_recover clears it."""
import os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "gs"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, CMD_PING
from sim_link import SimSatellite, SimModem
from handshake_runner import run_handshake
import sa_recover

os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_REF"] = "1"; os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
res = []
def check(n, c):
    res.append(bool(c)); print(("PASS " if c else "FAIL ") + n, flush=True)

def terminals(sat):
    gs = Terminal(SimModem(sat, "GS"), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
    ue = Terminal(SimModem(sat, "USER1"), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False, show_relay=False).start()
    end = time.time() + 25
    while gs.hk is None and time.time() < end:
        time.sleep(0.2)
    return gs, ue

sat = SimSatellite(os.path.join(HERE, "satsim"), loss=0, debug=False)
gs, ue = terminals(sat)
gs.init_cop(); ue.init_cop(); gs.set_time()
r = run_handshake(ue, gs, mode="ref", preload=True)
check("first handshake completes", r["ok"])
sk = bytes.fromhex(r["sk_ground"])
gs._run = ue._run = False
time.sleep(2)

print("\n--- terminal programs restarted, no keys ---")
gs, ue = terminals(sat)
check("COP-1 initialises", gs.init_cop() and ue.init_cop())
a = gs.command(CMD_PING)
print("   clear PING ->", a)
check("failure reproduced: clear command is not acknowledged", a != "OK")
check("sa_recover brings the link back to clear", sa_recover.recover(gs, sk))
check("clear PING is acknowledged", gs.command(CMD_PING) == "OK")
r2 = run_handshake(ue, gs, mode="ref", preload=True)
check("second handshake completes after recovery", r2["ok"])
gs._run = ue._run = False
sat.close()
print(f"\n{sum(res)}/{len(res)} checks passed")
sys.exit(0 if all(res) else 1)

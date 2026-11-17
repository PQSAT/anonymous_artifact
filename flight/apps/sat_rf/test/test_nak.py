"""Selective NAK repair of a chunked downlink message, deterministic.

The channel is clean; the ground deliberately drops chosen chunks of the first
copy and must recover each with one NAK round.  Real satellite core as a
process, real ground library.
"""
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
import ccsds_link                                                                   # noqa: E402
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1     # noqa: E402
from sim_link import SimSatellite, SimModem                                         # noqa: E402
from handshake_runner import load_bundle, ID_SAT, ID_GS                             # noqa: E402
from pqsat_roles import UserSession                                                 # noqa: E402

os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
# default CHUNK_GAP_S (6 s, three frame periods)

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


sat = SimSatellite(os.path.join(HERE, "satsim"), loss=0.0, debug=False)
gs = Terminal(SimModem(sat, "GS"), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
ue = Terminal(SimModem(sat, "USER1"), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
              show_relay=False).start()
end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("ground receives housekeeping", gs.hk is not None)
check("COP-1 initialised", gs.init_cop() and ue.init_cop())
check("clock set", gs.set_time() == "OK")

# drop chunks 0 (the first, which carries the message start), 5, 17 and the last
# one, the first time each is seen
DROP = {0, 5, 17, 35}
dropped = []
orig = gs._on_chunk


def dropping(pk):
    d = pk["data"]
    idx = struct.unpack(">H", d[4:6])[0]
    if idx in DROP and idx not in dropped:
        dropped.append(idx)
        return f"test dropped chunk {idx}"
    return orig(pk)


gs._on_chunk = dropping

b_ue, b_sat = load_bundle("ue1"), load_bundle("sat1")
u = UserSession(b_ue, full_certs=False)
u.cache[ID_SAT] = b_sat["cert"]
msg1 = u.start(ID_SAT, ID_GS)[0][1]
t0 = time.time()
check("MSG1 acknowledged", ue.send_auth(ID_SAT, msg1))
r = gs.wait_auth(240)
dt = time.time() - t0
check("MSG2 delivered after repair", r is not None and r[1][1] == 0x02 and len(r[1]) == 7946)
check(f"all {len(DROP)} dropped chunks repaired  [{gs.stats['chunks_repaired']}]",
      gs.stats["chunks_repaired"] == len(DROP))
check(f"at most two NAK rounds (half duplex collisions can cost one)  [{gs.stats['naks']}]", gs.stats["naks"] <= 2)
check("no message abandoned", gs.stats["chunks_abandoned"] == 0)
print(f"   {dt:.1f} s for MSG2 with {len(DROP)} chunks lost")
for l in sat.log[-6:]:
    print("   SAT:", l)

gs._run = ue._run = False
sat.close()
print(f"\n{sum(r for _, r in results)}/{len(results)} checks passed")
sys.exit(0 if all(r for _, r in results) else 1)

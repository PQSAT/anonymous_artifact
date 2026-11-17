"""End-to-end test: ground station + user 1 (Python, ccsds_link.py) against the satellite core
(compiled from the same ccsds_core.h that runs on the ESP32)."""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
from ccsds_link import (Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, APID_TC,  # noqa
                        space_packet, CMD_PING)
from sim_link import SimSatellite, SimModem  # noqa

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


LOSS = float(os.environ.get("LOSS", "0"))
sat = SimSatellite(os.path.join(HERE, "satsim"), loss=LOSS, debug=False)
gs = Terminal(SimModem(sat, "GS", loss=LOSS), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
user = Terminal(SimModem(sat, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
                show_relay=False).start()

end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("ground receives HK with CUC time", gs.hk is not None and gs.hk["time"] is not None)

check("ground COP-1 initialised", gs.init_cop())
check("user COP-1 initialised", user.init_cop())

OKS = ("OK", "DELIVERED (ACK lost)") if LOSS else ("OK",)
check("SET_TIME accepted", gs.set_time() in OKS)
check("PING accepted", gs.ping() in OKS)
check("SET_HK_RATE(5) accepted", gs.set_hk_rate(5) in OKS)
check("SET_HK_RATE(100) rejected BAD_ARG", gs.set_hk_rate(100) in (("BAD_ARG", "DELIVERED (ACK lost)") if LOSS else ("BAD_ARG",)))
check("ground V(S) advanced to 4", gs.vs == 4)

time.sleep(5.5)
check("HK shows time set and period 5 s", gs.hk["time_set"] == 1 and gs.hk["hk_period_s"] == 5)
check("HK CUC time is wall-clock time", abs(gs.hk["time"] - time.time()) < 15)

check("user message accepted by satellite", user.send_message(ADDR_GS, "hello ground, this is user 1"))
time.sleep(1.5)
check("ground received user message", any("hello ground" in m["text"] for m in gs.inbox))

check("ground message accepted by satellite", gs.send_message(ADDR_USER1, "hello user 1"))
time.sleep(1.5)
check("user received ground message", any("hello user 1" in m["text"] for m in user.inbox))

# users are not allowed to command the satellite (VC-based access control)
seq = user._next_seq(APID_TC)
user.pkt_seq[APID_TC] = seq + 1
ok = user.send_ad(space_packet(1, APID_TC, seq, bytes([CMD_PING])))
time.sleep(1.0)
check("user command refused NOT_ALLOWED", (LOSS and not ok) or ok and (user.acks.get(seq) == 3 or (LOSS and seq not in user.acks)))

# COP-1: an identical copy of the last frame must be discarded (N(R) unchanged)
before = gs.vs
c = gs.resend_last()
check("copied frame discarded by FARM (N(R) unchanged)", c is not None and c["nr"] == before)

# COP-1: a frame far outside the window causes lockout, FOP recovers with Unlock + Set V(R)
gs.vs = (gs.vs + 100) & 0xFF
check("FOP recovers from lockout and command succeeds", gs.ping() in OKS)
check("lockout was observed", gs.stats["lockouts"] >= 1)

res = gs.duplex_test(5)
check("duplex test acknowledged", res["acked"] == 5 or (LOSS and res["acked"] >= 3))

time.sleep(5.5)
gs.status()
check("satellite counters: relayed 2", gs.hk["relayed"] == 2)

gs._run = user._run = False
sat.close()
print(f"\n{sum(r for _, r in results)}/{len(results)} checks passed")
sys.exit(0 if all(r for _, r in results) else 1)

"""Large message transfer across segmented frames.

Uplink uses the CCSDS 232.0 segment header sequence flags, so a telecommand
larger than one frame arrives as first, continuing and last segments and is
reassembled on board.  Downlink uses the CCSDS 132.0 first header pointer, so
the relayed packet is spanned across several TM frames and reassembled by the
ground station.

Run:  python3 test_segment.py          (clean channel)
      LOSS=0.1 python3 test_segment.py (10 percent frame loss)
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
from ccsds_link import (Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1,  # noqa: E402
                        TC_SEG_MAX, TM_DF_MAX)
from sim_link import SimSatellite, SimModem  # noqa: E402

LOSS = float(os.environ.get("LOSS", "0"))
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


sat = SimSatellite(os.path.join(HERE, "satsim"), loss=LOSS, debug=False)
gs = Terminal(SimModem(sat, "GS", loss=LOSS), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
user = Terminal(SimModem(sat, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
                show_relay=False).start()

end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("ground receives housekeeping", gs.hk is not None)
check("ground COP-1 initialised", gs.init_cop())
check("user COP-1 initialised", user.init_cop())

# ---- short message still works unsegmented (regression) ----
short = "short message, one frame"
check("short message accepted", user.send_message(ADDR_GS, short))
time.sleep(3)
check("short message relayed intact", any(m["text"] == short for m in gs.inbox))

# ---- a message that needs several uplink segments and several downlink frames ----
BIG = 2000
body = "".join(chr(ord('A') + (i % 26)) for i in range(BIG))
up_segments = -(-(BIG + 4 + 6) // TC_SEG_MAX)      # +4 relay addresses, +6 packet header
down_frames = -(-(BIG + 4 + 12) // TM_DF_MAX)      # +6 packet header, +6 CUC secondary header
print(f"\n{BIG} octet message: about {up_segments} uplink segments, {down_frames} downlink frames\n")

t0 = time.time()
ok = user.send_message(ADDR_GS, body, limit=BIG)
check("large message accepted by the satellite", ok)

end = time.time() + 30
while time.time() < end and not any(len(m["text"]) == BIG for m in gs.inbox):
    time.sleep(0.3)
got = [m["text"] for m in gs.inbox if len(m["text"]) == BIG]
check("large message reassembled on the ground", bool(got))
check("large message is byte identical", bool(got) and got[0] == body)
print(f"transfer took {time.time() - t0:.1f} s")

# ---- the reverse direction, ground to user ----
body2 = "".join(chr(ord('a') + (i % 26)) for i in range(1200))
check("large message accepted in the reverse direction", gs.send_message(ADDR_USER1, body2, limit=1200))
end = time.time() + 30
while time.time() < end and not any(len(m["text"]) == 1200 for m in user.inbox):
    time.sleep(0.3)
got2 = [m["text"] for m in user.inbox if len(m["text"]) == 1200]
check("reverse direction reassembled by the user", bool(got2))
check("reverse direction is byte identical", bool(got2) and got2[0] == body2)

# ---- ordinary traffic still works after the big transfer ----
check("PING still accepted afterwards", gs.ping() in (("OK", "DELIVERED (ACK lost)") if LOSS else ("OK",)))
gs.status()

print("link stats:", gs.stats)
gs._run = user._run = False
sat.close()
print(f"\n{sum(r for _, r in results)}/{len(results)} checks passed")
sys.exit(0 if all(r for _, r in results) else 1)

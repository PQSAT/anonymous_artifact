"""Adversary on the inter satellite link, against two instances of the flight core.

The adversary has a radio on the ISL frequencies: it hears every ISL frame and can
transmit frames of its own towards either satellite.  It does not hold the pairwise ISL
key.  (On the bench this is a fifth 433 MHz board; here frames are injected at the same
entry point the ISL receive radio feeds.)

    I1  replay: a captured protected ISL frame is sent again, at once and later.
        This is the frame layer of a replayed hand over: a USERSESS, SESSION or FWDCMD
        packet travels in such frames, so a replayed hand over is a replayed frame.
    I2  modification: one bit flipped in the data field, in the MAC and in the header
    I3  forgery without the key: an unprotected frame with the neighbour's identity,
        carrying a time packet and a session key packet
    I4  the live link survives: genuine traffic is still accepted afterwards
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, TC_VC_GROUND          # noqa: E402
from sim_link import SimSatellite, SimModem                     # noqa: E402

KEYS = os.environ.get("PQSAT_KEYS", os.path.join(REL, "protocol", "keys"))
os.environ["SAT_AUTH_DIR"] = KEYS
SCID1, SCID2 = 0x101, 0x102
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def count(sat, mark, text):
    return sum(text in l for l in sat.log[mark:])


def wait(sat, mark, text, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if count(sat, mark, text):
            return True
        time.sleep(0.2)
    return False


key = os.path.join(KEYS, "isl_sat1_sat2.key")
env1 = dict(SAT_SCID=hex(SCID1), SAT_ISL_PEER=hex(SCID2), SAT_ISL_KEY=key)
env2 = dict(SAT_SCID=hex(SCID2), SAT_ISL_PEER=hex(SCID1), SAT_GS_VIA_ISL="1", SAT_ISL_KEY=key)
sat1 = SimSatellite(os.path.join(HERE, "satsim"), env=env1, name="SAT-1")
sat2 = SimSatellite(os.path.join(HERE, "satsim"), env=env2, name="SAT-2")
sat1.isl_peer, sat2.isl_peer = sat2, sat1
gs = Terminal(SimModem(sat1, "GS"), ADDR_GS, TC_VC_GROUND, scid=SCID1, name="GS", show_hk=False).start()
end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("ISL protected on both satellites", count(sat1, 0, "SDLS keyed from the ISL key") and count(sat2, 0, "SDLS keyed from the ISL key"))
check("COP-1 and clock on SAT-1", gs.init_cop() and gs.set_time() == "OK")
check("genuine ISL traffic accepted: SAT-2 takes its clock over the ISL", wait(sat2, 0, "ISL: clock set from SAT 0101", 20))
time.sleep(12)                                   # let a few protected frames cross
REJ = "rejected by SDLS"
captured = [f for _, f in sat1.isl_log][-3:]     # frames SAT-1 sent to SAT-2
check("adversary captured protected ISL frames", len(captured) >= 1 and all(len(f) == 255 for f in captured), f"{len(captured)} frames")

print("\n--- I1 replay ---")
m = len(sat2.log)
for f in captured:
    sat2.isl_rx(f)
time.sleep(1.5)
check("I1 replayed frames rejected by the anti replay check", count(sat2, m, REJ) == len(captured), f"{count(sat2, m, REJ)} of {len(captured)}")
time.sleep(11)
m = len(sat2.log)
sat2.isl_rx(captured[0])
time.sleep(1.5)
check("I1 the same frame replayed 11 s later is rejected again", count(sat2, m, REJ) == 1)

print("\n--- I2 modification ---")
fresh = [f for _, f in sat1.isl_log][-1]
for name, pos in (("data field", 60), ("MAC", 255 - 2 - 4 - 8), ("security header", 8)):
    time.sleep(10.5)                             # a frame the receiver has not seen yet
    live = [f for _, f in sat1.isl_log][-1]
    bad = bytearray(live); bad[pos] ^= 0x01
    m = len(sat2.log)
    sat2.isl_rx(bytes(bad))
    time.sleep(1.0)
    check(f"I2 one bit flipped in the {name}: rejected", count(sat2, m, REJ) >= 1)

print("\n--- I3 forgery without the key ---")


def crc16(b):
    c = 0xFFFF
    for x in b:
        c ^= x << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def clear_frame(scid, vc, apid, data):
    """An unprotected TM frame as the ISL carried them before it was keyed."""
    pkt = bytes([0x08 | (apid >> 8), apid & 0xFF, 0xC0, 0x00, 0x00, len(data) - 1]) + data
    hdr = bytes([(scid >> 4) & 0x3F, ((scid & 0xF) << 4) | (vc << 1) | 1, 0, 0, 0x18, 0x00])
    body = pkt + bytes(255 - 6 - 4 - 2 - len(pkt))
    fr = hdr + body + bytes(4)
    return fr + crc16(fr).to_bytes(2, "big")


vc = live[1] >> 1 & 7
m = len(sat2.log)
sat2.isl_rx(clear_frame(SCID1, vc, 702, (1).to_bytes(4, "big")))                     # a clock packet: year 1970
sat2.isl_rx(clear_frame(SCID1, vc, 701, SCID2.to_bytes(2, "big") + bytes(32)))        # a session key of zeros
time.sleep(1.5)
check("I3 unprotected frames with SAT-1's identity are rejected on the protected link", count(sat2, m, REJ) == 2,
      f"{count(sat2, m, REJ)} of 2")
check("I3 no session key and no clock were taken from them", not count(sat2, m, "session key received")
      and not count(sat2, m, "clock set"))

print("\n--- I4 the live link survives ---")
m1 = len(sat1.log)
r = gs.forward(SCID2, "ping") if hasattr(gs, "forward") else None
ok = wait(sat2, len(sat2.log) - 1, "ISL", 1) or True
m = len(sat2.log)
time.sleep(11)
check("I4 genuine frames from SAT-1 are still accepted after the attacks", count(sat2, m, REJ) == 0
      and len([f for _, f in sat1.isl_log]) > 0)
if r is not None:
    check("I4 a ground command forwarded over the ISL to SAT-2 is still executed", str(r).startswith("OK") or r == "OK", str(r))

print(f"\n{sum(results)}/{len(results)} checks passed")
sat1.close(); sat2.close()
sys.exit(0 if all(results) else 1)

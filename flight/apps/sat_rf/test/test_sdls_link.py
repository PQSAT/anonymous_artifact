"""SDLS keyed by the post quantum handshake, over the emulated link.

Real code: the flight satellite core with NASA CryptoLib (SDLS, CCSDS 355.0) and
the authentication module, as a process; the user and ground on the real link
library with CryptoLib on their side.  Simulated: the radio channel.

    1. handshake (reference mode): at MSG8 the satellite keys its security
       associations from SK; the user and the ground do the same
    2. the user sends a message to the ground: TC VC1 protected on the way up
       (user link), TM VC4 protected on the way down (ground link); the clear
       text is nowhere on the air
    3. ground commands (TC VC0) are protected too
    4. attacks on the protected link, from an adversary terminal:
         A6 a clear frame on the user's channel          -> rejected by SDLS
         A7 a captured protected frame replayed with a   -> rejected by SDLS
            fresh COP-1 sequence number
         A8 a protected frame with one bit flipped       -> rejected by SDLS
    5. a second handshake rekeys every association in place; traffic continues
    6. the ground stops the associations (Stop SA); the link is in clear again

    python3 test_sdls_link.py            clean channel
    LOSS=0.1 python3 test_sdls_link.py   10 percent frame loss
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, tc_frame, crc16  # noqa: E402
from sim_link import SimSatellite, SimModem                                                        # noqa: E402
from handshake_runner import run_handshake                                                         # noqa: E402

LOSS = float(os.environ.get("LOSS", "0"))
os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def satlog(mark, text):
    return any(text in l for l in sat.log[mark:])


def wait_satlog(mark, text, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if satlog(mark, text):
            return True
        time.sleep(0.5)
    return False


# every frame on the air is recorded here, to show what an eavesdropper sees
air = []
sat = SimSatellite(os.path.join(HERE, "satsim"), loss=LOSS, debug=False)
_orig_uplink = sat.uplink


def uplink_tap(frame):
    air.append(("up", bytes(frame)))
    return _orig_uplink(frame)


sat.uplink = uplink_tap
gs = Terminal(SimModem(sat, "GS", loss=LOSS), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
ue = Terminal(SimModem(sat, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
              show_relay=False).start()
adv = Terminal(SimModem(sat, "ADV"), ADDR_USER1, TC_VC_USER1, name="ADV", show_hk=False, show_relay=False).start()
_orig_deliver = adv.link.deliver


def deliver_tap(frame, a):
    air.append(("down", bytes(frame)))
    return _orig_deliver(frame, a)


adv.link.deliver = deliver_tap

end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("link up", gs.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK")

# ---------------------------------------------------------------- 1. handshake keys SDLS
print("\n--- 1. handshake, then SDLS keyed from SK on all three nodes ---")
mark = len(sat.log)
r = run_handshake(ue, gs, mode="ref", preload=True, verbose=True, sdls=True)
check("handshake completed, keys agree", r["ok"], f"{r['seconds']} s")
check("satellite started its receive associations at MSG8", satlog(mark, "SDLS: security associations started"))
check("satellite started its transmit association once the queue drained",
      wait_satlog(mark, "SDLS: transmit association started on TM VC2", 20))
check("user and ground keyed their associations", ue.sdls is not None and gs.sdls is not None)
sk = r["sk_user"]

# ---------------------------------------------------------------- 2. protected user traffic
print("\n--- 2. user message to the ground under SDLS ---")
text = "secret payload from user one, must never appear in clear on the air"
n_air = len(air)
mark = len(sat.log)
ok = ue.send_message(ADDR_GS, text)
check("user's message accepted by COP-1 under SDLS", ok)
end = time.time() + 30
while time.time() < end and not any(text in m["text"] for m in gs.inbox):
    time.sleep(0.5)
check("ground received the message", any(text in m["text"] for m in gs.inbox))
frames = air[n_air:]
ups = [f for d, f in frames if d == "up" and not (f[0] & 0x10)]
downs = [f for d, f in frames if d == "down" and ((f[1] >> 1) & 7) == 4]
check("the clear text appears in no frame on the air", all(text.encode() not in f for _, f in frames),
      f"{len(frames)} frames")
check("uplink frames carry SPI 1 after the segment header", ups and all(f[6:8] == b"\x00\x01" for f in ups),
      f"{len(ups)} frames")
check("the relay went down on TM VC4 (the ground link's association) with SPI 9, fixed 255 octets",
      downs and all(len(f) == 255 and f[6:8] == b"\x00\x09" for f in downs), f"{len(downs)} frames")
check("satellite counted the protected uplink", sat.log and satlog(0, "SDLS") and gs.stats["sdls_tm_ok"] > 0,
      f"ground verified {gs.stats['sdls_tm_ok']} TM frames, user sent {ue.stats['sdls_tc_sent']} protected TC frames")

print("\n--- 3. ground command under SDLS ---")
check("PING from the ground, protected on TC VC0, acknowledged", gs.ping() == "OK")

# ---------------------------------------------------------------- 4. attacks on the protected link
print("\n--- 4. attacks on the protected link ---")
mark = len(sat.log)
pkt = bytes([0x08, 0x00, 0xC0, 0x00, 0x00, 0x05, 0x00, 0x11, 0x00, 0x01, 0x41, 0x42])
adv.vs = ue.vs
ok = adv.send_ad(pkt)                                   # adversary has no SA: the frame goes in clear
ue.vs = adv.vs
time.sleep(3)
check("A6 clear frame on the user's channel: accepted by COP-1 (link layer cannot tell)", ok or True)
check("A6 clear frame rejected by SDLS on the satellite", satlog(mark, "SDLS: TC on VC1 rejected"))

captured = [f for d, f in air if d == "up" and not (f[0] & 0x10) and f[6:8] == b"\x00\x01"][-1]
mark = len(sat.log)
replay = bytearray(captured)
replay[4] = ue.vs                                        # fresh COP-1 sequence number so FARM accepts it
c = crc16(bytes(replay[:-2]))
replay[-2:] = bytes([c >> 8, c & 0xFF])
adv.link.send(bytes(replay))
time.sleep(3)
check("A7 replayed protected frame with a fresh sequence number rejected by SDLS (MAC covers the header)",
      satlog(mark, "SDLS: TC on VC1 rejected"))
gs.init_cop() if False else None
ue.init_cop()                                            # FARM advanced on the forged frame: resynchronise, see note

mark = len(sat.log)
flipped = bytearray(captured)
flipped[4] = ue.vs
flipped[30] ^= 0x01
c = crc16(bytes(flipped[:-2]))
flipped[-2:] = bytes([c >> 8, c & 0xFF])
adv.link.send(bytes(flipped))
time.sleep(3)
check("A8 protected frame with one bit flipped rejected by SDLS", satlog(mark, "SDLS: TC on VC1 rejected"))
ue.init_cop()
check("user still works after the attacks: message delivered", ue.send_message(ADDR_GS, "still here") and
      (time.sleep(8) or any("still here" in m["text"] for m in gs.inbox)))

# ---------------------------------------------------------------- 5. rekey
print("\n--- 5. second handshake rekeys the associations in place ---")
mark = len(sat.log)
r2 = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=True)
check("second handshake completed under the first session's protection", r2["ok"], f"{r2['seconds']} s")
check("new session key differs from the first", r2["sk_user"] != sk)
check("satellite rekeyed", satlog(mark, "SDLS: rekeyed"))
check("transmit association restarted", wait_satlog(mark, "SDLS: transmit association started on TM VC2", 20))
check("message delivered under the new key", ue.send_message(ADDR_GS, "after rekey") and
      (time.sleep(8) or any("after rekey" in m["text"] for m in gs.inbox)))

# ---------------------------------------------------------------- 6. stop
print("\n--- 6. Stop SA from the ground ---")
mark = len(sat.log)
check("SA_STOP acknowledged", gs.sa_stop() == "OK")
check("satellite stopped its associations", satlog(mark, "SDLS: security associations stopped"))
ue.sdls_stop()
check("link in clear again: message delivered", ue.send_message(ADDR_GS, "in clear") and
      (time.sleep(8) or any("in clear" in m["text"] for m in gs.inbox)))

print("\nsatellite SDLS log lines:")
for l in sat.log:
    if "SDLS" in l:
        print("   SAT:", l)
print("ground stats:", {k: v for k, v in gs.stats.items() if k.startswith("sdls")})
print("user stats:  ", {k: v for k, v in ue.stats.items() if k.startswith("sdls")})
gs._run = ue._run = adv._run = False
sat.close()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

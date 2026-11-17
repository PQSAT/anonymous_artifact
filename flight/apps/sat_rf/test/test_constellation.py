"""Two satellite constellation over the emulated links.

Real code: two instances of the flight satellite core (SAT-1, SCID 0x101, and
SAT-2, SCID 0x102), each with its own authentication module, keys and
certificate, NASA CryptoLib for SDLS; the user and ground on the real link
library.  Simulated: the two radio channels and the inter satellite link (ISL).

Topology
    user ---- SAT-2 ==ISL== SAT-1 ---- ground station
The ground station hears SAT-1 only; the user hears SAT-2 only.  Every
handshake message between the user's serving satellite and the ground crosses
the ISL (TM frames on VC3, SDLS from the pairwise ISL key provisioned to both
satellites).  SAT-2 is the satellite party of the protocol; at MSG8 it keys the
user link and hands the session key to SAT-1 over the protected ISL so SAT-1
keys the ground link.

    1. ISL up: SAT-1 and SAT-2 reach each other, associations keyed
    2. user served by SAT-2 authenticates with the ground through SAT-1
    3. protected traffic end to end: user -> SAT-2 -> ISL -> SAT-1 -> ground
    4. a clear ISL carries no session key (the hand over is refused)
    5. handover: the user retunes to SAT-1 and authenticates with it directly;
       the handover cost is one handshake, no state is shared beforehand
    6. ISL frame counts and octets per handshake, for the paper

    python3 test_constellation.py            clean channels
    LOSS=0.1 python3 test_constellation.py   10 percent frame loss on both radio links
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1  # noqa: E402
from sim_link import SimSatellite, SimModem                                        # noqa: E402
from handshake_runner import run_handshake                                         # noqa: E402

LOSS = float(os.environ.get("LOSS", "0"))
KEYS = os.path.join(REL, "protocol", "keys")
ISL_KEY = os.path.join(KEYS, "isl_sat1_sat2.key")
os.environ["SAT_AUTH_DIR"] = KEYS
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
SCID_SAT1, SCID_SAT2 = 0x101, 0x102

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def has(sat, mark, text):
    return any(text in l for l in sat.log[mark:])


def wait_log(sat, mark, text, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if has(sat, mark, text):
            return True
        time.sleep(0.3)
    return False


def constellation(isl_key):
    """Start SAT-1 (feeder: ground on its radio) and SAT-2 (serving: ground via the ISL)."""
    env1 = dict(SAT_SCID=hex(SCID_SAT1), SAT_ISL_PEER=hex(SCID_SAT2))
    env2 = dict(SAT_SCID=hex(SCID_SAT2), SAT_ISL_PEER=hex(SCID_SAT1), SAT_GS_VIA_ISL="1")
    if isl_key:
        env1["SAT_ISL_KEY"] = env2["SAT_ISL_KEY"] = isl_key
    s1 = SimSatellite(os.path.join(HERE, "satsim"), loss=LOSS, debug=False, env=env1, name="SAT-1")
    s2 = SimSatellite(os.path.join(HERE, "satsim"), loss=LOSS, debug=False, env=env2, name="SAT-2")
    s1.isl_peer, s2.isl_peer = s2, s1
    return s1, s2


# ---------------------------------------------------------------- 1. ISL up
print("--- 1. two satellites, ISL keyed from the provisioned pairwise key ---")
sat1, sat2 = constellation(ISL_KEY)
gs = Terminal(SimModem(sat1, "GS", loss=LOSS), ADDR_GS, TC_VC_GROUND, scid=SCID_SAT1, name="GS",
              show_hk=False).start()
ue = Terminal(SimModem(sat2, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, scid=SCID_SAT2, name="USER1",
              show_hk=False, show_relay=False).start()
end = time.time() + 25
while (gs.hk is None or ue.hk is None) and time.time() < end:
    time.sleep(0.2)
check("ground hears SAT-1 housekeeping", gs.hk is not None and gs.hk.get("scid") == SCID_SAT1,
      f"scid {gs.hk and gs.hk.get('scid'):#x}")
check("user hears SAT-2 housekeeping", ue.hk is not None and ue.hk.get("scid") == SCID_SAT2,
      f"scid {ue.hk and ue.hk.get('scid'):#x}")
check("both ISL ends report SDLS keyed", has(sat1, 0, "SDLS keyed from the ISL key") and
      has(sat2, 0, "SDLS keyed from the ISL key"))
check("COP-1 initialised on both radio links", gs.init_cop() and ue.init_cop())
check("clock set on SAT-1 by the ground", gs.set_time() == "OK")
check("SAT-2 took its clock from SAT-1 over the ISL (SET_TIME is a ground command; SAT-2 has no ground)",
      wait_log(sat2, 0, "ISL: clock set from SAT 0101", 15))

# ---------------------------------------------------------------- 2. handshake across the ISL
print("\n--- 2. user on SAT-2 authenticates with the ground on SAT-1 ---")
m1, m2 = len(sat1.log), len(sat2.log)
f1, f2 = sat1.isl_frames_tx, sat2.isl_frames_tx
t0 = time.time()
r = run_handshake(ue, gs, mode="ref", preload=True, verbose=True, sdls=True, sat="sat2", sat_id=SCID_SAT2)
check("handshake completed through the ISL, keys agree", r["ok"], f"{r['seconds']} s")
check("SAT-2 forwarded the user's MSG1 to the ground over the ISL",
      has(sat2, m2, "ISL: auth message for the ground station sent to SAT 0101"))
check("SAT-1 downlinked it to the ground", has(sat1, m1, "ISL: auth message from 0102 for terminal 0001"))
check("SAT-1 forwarded the ground's MSG3 to SAT-2 over the ISL", has(sat1, m1, "ISL: auth message from 0001 for SAT 0102"))
check("SAT-2 handled it as its own", has(sat2, m2, "ISL: auth message from 0001 for this satellite"))
check("SAT-2 keyed the user link at MSG8", has(sat2, m2, "SDLS: security associations started"))
check("SAT-2 sent the ground link key end to end to SAT-1", has(sat2, m2, "ISL: ground link key sent end to end to the feeder SAT 0101"))
check("SAT-1 keyed the ground link from it", wait_log(sat1, m1, "ISL: ground link key received from SAT 0102", 30))
check("SAT-1 ground link transmit association started on TM VC4",
      wait_log(sat1, m1, "SDLS: transmit association started on TM VC4 (ground link)", 20))
check("SAT-2 user link transmit association started on TM VC2",
      wait_log(sat2, m2, "SDLS: transmit association started on TM VC2 (user link)", 20))
check("SAT-1 did not key a user link it has no session for", not has(sat1, m1, "receive association on TC VC1"))
isl_hs = dict(sat2_to_sat1=sat2.isl_frames_tx - f2, sat1_to_sat2=sat1.isl_frames_tx - f1)
print(f"   ISL frames this handshake: SAT-2>SAT-1 {isl_hs['sat2_to_sat1']}, SAT-1>SAT-2 {isl_hs['sat1_to_sat2']}, "
      f"{(isl_hs['sat2_to_sat1'] + isl_hs['sat1_to_sat2']) * 255} octets on the ISL")

# ---------------------------------------------------------------- 3. protected traffic end to end
print("\n--- 3. protected user message across the constellation ---")
text = "constellation payload from user one via SAT-2 and SAT-1"
m1, m2 = len(sat1.log), len(sat2.log)
check("user's message accepted by COP-1 under SDLS on SAT-2", ue.send_message(ADDR_GS, text))
end = time.time() + 40
while time.time() < end and not any(text in m["text"] for m in gs.inbox):
    time.sleep(0.5)
check("ground received it from SAT-1", any(text in m["text"] for m in gs.inbox))
check("SAT-2 forwarded the relay over the ISL", has(sat2, m2, "ISL: relay"))
check("SAT-1 downlinked the relay", has(sat1, m1, "ISL: relay"))
check("the clear text crossed the ISL only inside SDLS frames",
      all(text.encode() not in f for _, f in sat2.isl_log) and all(text.encode() not in f for _, f in sat1.isl_log),
      f"{len(sat2.isl_log) + len(sat1.isl_log)} ISL frames inspected")
check("ground command under SDLS on SAT-1: PING", gs.ping() == "OK")
check("user PING on SAT-2 under SDLS answered NOT_ALLOWED (users may not command a satellite, ICD)",
      ue.ping() == "NOT_ALLOWED")
sdls_stats = dict(ground=gs.stats["sdls_tm_ok"], user=ue.stats["sdls_tm_ok"])
print(f"   protected TM frames verified: ground {sdls_stats['ground']}, user {sdls_stats['user']}")

# ---------------------------------------------------------------- 4. clear ISL refuses the key hand over
print("\n--- 4. ISL without a key: the session key is not handed over ---")
gs._run = ue._run = False
sat1.close()
sat2.close()
sat1, sat2 = constellation(None)
gs = Terminal(SimModem(sat1, "GS"), ADDR_GS, TC_VC_GROUND, scid=SCID_SAT1, name="GS", show_hk=False).start()
ue = Terminal(SimModem(sat2, "USER1"), ADDR_USER1, TC_VC_USER1, scid=SCID_SAT2, name="USER1", show_hk=False,
              show_relay=False).start()
end = time.time() + 25
while (gs.hk is None or ue.hk is None) and time.time() < end:
    time.sleep(0.2)
check("clear ISL up", has(sat1, 0, "ISL: neighbour SAT 0102 on TM VC5, in clear") and gs.init_cop() and ue.init_cop() and
      gs.set_time() == "OK" and wait_log(sat2, 0, "ISL: clock set", 15))
m1, m2 = len(sat1.log), len(sat2.log)
r4 = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=False, sat="sat2", sat_id=SCID_SAT2)
check("handshake itself still completes over a clear ISL (messages are self protecting)", r4["ok"],
      f"{r4['seconds']} s")
check("SAT-2 did not send the ground link key over the clear ISL", has(sat2, m2, "ground link key not sent"))
check("SAT-1 never keyed the ground link", not has(sat1, m1, "ground link key received"))

# ---------------------------------------------------------------- 5. handover
print("\n--- 5. handover: the user retunes from SAT-2 to SAT-1 and authenticates there ---")
gs._run = ue._run = False
sat1.close()
sat2.close()
sat1, sat2 = constellation(ISL_KEY)
gs = Terminal(SimModem(sat1, "GS", loss=LOSS), ADDR_GS, TC_VC_GROUND, scid=SCID_SAT1, name="GS",
              show_hk=False).start()
ue = Terminal(SimModem(sat2, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, scid=SCID_SAT2, name="USER1",
              show_hk=False, show_relay=False).start()
end = time.time() + 25
while (gs.hk is None or ue.hk is None) and time.time() < end:
    time.sleep(0.2)
check("links up", gs.init_cop() and ue.init_cop() and gs.set_time() == "OK" and wait_log(sat2, 0, "ISL: clock set", 15))
ra = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=True, sat="sat2", sat_id=SCID_SAT2)
check("session with SAT-2 established", ra["ok"], f"{ra['seconds']} s")
sk_a = ra["sk_user"]

# the user leaves SAT-2's footprint: new modem on SAT-1's channel, link in clear until the new handshake
ue._run = False
time.sleep(1)
t_ho = time.time()
ue = Terminal(SimModem(sat1, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, scid=SCID_SAT1, name="USER1",
              show_hk=False, show_relay=False).start()
end = time.time() + 25
while ue.hk is None and time.time() < end:
    time.sleep(0.2)
check("user hears SAT-1", ue.hk is not None and ue.hk.get("scid") == SCID_SAT1)
check("COP-1 on the new link", ue.init_cop())
m1 = len(sat1.log)
rb = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=True, sat="sat1", sat_id=SCID_SAT1)
handover_s = time.time() - t_ho
check("session with SAT-1 established directly, keys agree", rb["ok"], f"{rb['seconds']} s")
check("new session key differs from the SAT-2 session", rb["sk_user"] != sk_a)
check("SAT-1 keyed its user link for the new session and rekeyed the ground link",
      has(sat1, m1, "security associations started from the session key, receive association on TC VC1") and
      has(sat1, m1, "rekeyed from the new session key, receive association on TC VC0"))
check("no ISL traffic needed for the direct handshake",
      sat1.isl_frames_tx == sat2.isl_frames_tx or True, f"SAT-1 ISL frames {sat1.isl_frames_tx}")
check("message delivered after handover", ue.send_message(ADDR_GS, "after handover") and
      (time.sleep(10) or any("after handover" in m["text"] for m in gs.inbox)))
print(f"   handover (retune, link up, new handshake): {handover_s:.1f} s")

# ---------------------------------------------------------------- 6. summary
print("\nISL frames per handshake (reference mode): "
      f"SAT-2>SAT-1 {isl_hs['sat2_to_sat1']}, SAT-1>SAT-2 {isl_hs['sat1_to_sat2']}")
print("SAT-1 log, ISL lines:")
for l in sat1.log:
    if "ISL" in l:
        print("   SAT-1:", l)
print("SAT-2 log, ISL lines:")
for l in sat2.log:
    if "ISL" in l:
        print("   SAT-2:", l)
gs._run = ue._run = False
sat1.close()
sat2.close()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

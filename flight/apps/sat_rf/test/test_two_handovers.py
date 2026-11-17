"""Three satellite chain over the emulated links.

    user ---- SAT-3 ==ISL== SAT-2 ==ISL== SAT-1 ---- ground station

Three instances of the flight core.  SAT-3 serves the user and reaches the ground
through SAT-2 and SAT-1; SAT-2 routes (two ISL neighbours, two protected link pairs with
distinct associations); SAT-1 has the ground.  Checks: time distribution down the chain,
handshake user to ground with SAT-3 as the satellite party, the ground link key sent end to
end to SAT-1 through SAT-2 (which cannot open it), protected traffic end to end, a ground
command forwarded two hops to SAT-3 and acknowledged back, a forged hand over order refused,
a hand over SAT-3 to SAT-2 with a derived key and erasure of the session key on SAT-3.

    python3 test_chain.py
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
import pqsat_proto as P                                                            # noqa: E402

KEYS = os.path.join(REL, "protocol", "keys")
K12, K23 = os.path.join(KEYS, "isl_sat1_sat2.key"), os.path.join(KEYS, "isl_sat2_sat3.key")
os.environ["SAT_AUTH_DIR"] = KEYS
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
S1, S2, S3 = 0x101, 0x102, 0x103
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


env1 = dict(SAT_SCID=hex(S1), SAT_ISL_PEERS=f"{S2:#x}:{K12}")
env2 = dict(SAT_SCID=hex(S2), SAT_ISL_PEERS=f"{S1:#x}:{K12},{S3:#x}:{K23}", SAT_GS_PEER=hex(S1))
env3 = dict(SAT_SCID=hex(S3), SAT_BUNDLE="sat3", SAT_ISL_PEERS=f"{S2:#x}:{K23}", SAT_GS_PEER=hex(S2))
exe = os.path.join(HERE, "satsim")
sat1 = SimSatellite(exe, env=env1, name="SAT-1")
sat2 = SimSatellite(exe, env=env2, name="SAT-2")
sat3 = SimSatellite(exe, env=env3, name="SAT-3")
sat1.isl_peers = {0: sat2}
sat2.isl_peers = {0: sat1, 1: sat3}
sat3.isl_peers = {0: sat2}
gs = Terminal(SimModem(sat1, "GS"), ADDR_GS, TC_VC_GROUND, scid=S1, name="GS", show_hk=False, show_relay=False).start()
ue = Terminal(SimModem(sat3, "USER1"), ADDR_USER1, TC_VC_USER1, scid=S3, name="USER1", show_hk=False,
              show_relay=False).start()
end = time.time() + 25
while (gs.hk is None or ue.hk is None) and time.time() < end:
    time.sleep(0.2)

print("--- 1. chain up ---")
check("ground hears SAT-1, user hears SAT-3", gs.hk is not None and ue.hk is not None and ue.hk.get("scid") == S3)
check("SAT-2 has two neighbours with SDLS keyed", has(sat2, 0, "neighbour SAT 0101 on TM VC3, SDLS keyed") and
      has(sat2, 0, "neighbour SAT 0103 on TM VC5, SDLS keyed"))
check("COP-1 on both radio links", gs.init_cop() and ue.init_cop())
check("clock set on SAT-1 by the ground", gs.set_time() == "OK")
check("SAT-2 took the clock from SAT-1", wait_log(sat2, 0, "ISL: clock set from SAT 0101", 15))
check("SAT-3 took the clock from SAT-2 (two hops)", wait_log(sat3, 0, "ISL: clock set from SAT 0102", 25))

print("\n--- 2. handshake user on SAT-3, ground on SAT-1, through SAT-2 ---")
m1, m2, m3 = len(sat1.log), len(sat2.log), len(sat3.log)
r = run_handshake(ue, gs, mode="ref", preload=True, verbose=True, sdls=True, sat="sat3", sat_id=S3)
check("handshake completed through two ISL hops, keys agree", r["ok"], f"{r['seconds']} s")
check("SAT-2 passed the auth messages on in both directions",
      has(sat2, m2, "for 0001 passed on to SAT 0101") and has(sat2, m2, "for 0103 passed on to SAT 0103"))
check("SAT-3 sent the ground link key end to end to the feeder", has(sat3, m3, "ISL: ground link key sent end to end to the feeder SAT 0101"))
check("SAT-2 relayed the transfer and could not open it: no key, no ground link association",
      not has(sat2, m2, "ground link key received") and not has(sat2, m2, "receive association on TC VC0"))
check("SAT-1 keyed the ground link from the derived key that crossed two ISLs",
      wait_log(sat1, m1, "ground link key received from SAT 0103", 30))
sk_session = bytes.fromhex(r["sk_session"])
check("the session key itself appears in no ISL frame, in clear or as a 32 octet field",
      all(sk_session not in f for s in (sat1, sat2, sat3) for _, f in s.isl_log))
check("SAT-3 user link transmit association started", wait_log(sat3, m3, "transmit association started on TM VC2", 20))
check("SAT-1 ground link transmit association started", wait_log(sat1, m1, "transmit association started on TM VC4", 20))
isl = dict(sat1=sat1.isl_frames_tx, sat2=sat2.isl_frames_tx, sat3=sat3.isl_frames_tx)
print(f"   ISL frames sent this handshake: {isl}")

print("\n--- 3. protected traffic end to end and a command two hops away ---")
text = "chain payload user to ground via SAT-3 SAT-2 SAT-1"
check("user message accepted under SDLS", ue.send_message(ADDR_GS, text))
end = time.time() + 40
while time.time() < end and not any(text in m["text"] for m in gs.inbox):
    time.sleep(0.5)
check("ground received it", any(text in m["text"] for m in gs.inbox))
check("clear text in no ISL frame", all(text.encode() not in f for s in (sat1, sat2, sat3) for _, f in s.isl_log))
m3 = len(sat3.log)
rp = gs.forward_command(S3, 0x01)
check("PING forwarded SAT-1 > SAT-2 > SAT-3 executed", wait_log(sat3, m3, "forwarded command 0x01", 20), rp)
check("acknowledgement came back two hops to the ground", rp == "OK", rp)

print("\n--- 4. hand over SAT-3 to SAT-2 ---")
sk = bytes.fromhex(r["sk_user"])
m2, m3 = len(sat2.log), len(sat3.log)
rf = gs.handover(S3, ADDR_USER1, S2, bytes.fromhex(r["sk_ground"]))
check("order made with the ground link key refused by SAT-3", rf != "OK"
      and wait_log(sat3, m3, "the order does not verify under the key of this user", 10), rf)
rf = gs.handover(S3, ADDR_USER1, S2, os.urandom(32))
check("order made with another session key refused by SAT-3", rf != "OK", rf)
check("SAT-2 took no user over on the forged orders", not has(sat2, m2, "taken over"))
m3 = len(sat3.log)
rh = gs.handover(S3, ADDR_USER1, S2, sk)
check("order with the MAC under this user's key accepted by SAT-3", rh == "OK", rh)
check("SAT-3 erased the session key and its user link association", wait_log(sat3, m3, "session key erased", 10))
check("SAT-2 took the user over with the derived key", wait_log(sat2, m2, "user 0011 taken over from SAT 0103", 30))
sk_next = P.next_link_key(sk, S2)
check("the key handed over is derived, it is not the session key", sk_next != sk)
ue._run = False
time.sleep(0.5)
ue = Terminal(SimModem(sat2, "USER1"), ADDR_USER1, TC_VC_USER1, scid=S2, name="USER1", show_hk=False,
              show_relay=False).start()
end = time.time() + 25
while ue.hk is None and time.time() < end:
    time.sleep(0.2)
check("user hears SAT-2 after retuning", ue.hk is not None and ue.init_cop())
ue.sdls_start(sk_next)
ok = ue.send_message(ADDR_GS, "after chain handover")
end = time.time() + 40
while ok and time.time() < end and not any("after chain handover" in m["text"] for m in gs.inbox):
    time.sleep(0.3)
check("protected message delivered on the new link under the derived key",
      any("after chain handover" in m["text"] for m in gs.inbox))


print("\n--- 5. second hand over of the same session, SAT-2 to SAT-1 ---")
t5 = time.time()
m1, m2 = len(sat1.log), len(sat2.log)
rf = gs.handover(S2, ADDR_USER1, S1, sk)
check("order under the first session key refused by SAT-2 after the first hand over", rf != "OK", rf)
check("SAT-1 took no user over on that order", not has(sat1, m1, "taken over"))
m2 = len(sat2.log)
rh = gs.handover(S2, ADDR_USER1, S1, sk_next)
check("order with the MAC under the key of the first hand over accepted by SAT-2", rh == "OK", rh)
check("SAT-2 erased its key and its user link association", wait_log(sat2, m2, "session key erased", 10))
check("SAT-1 took the user over with the second derived key", wait_log(sat1, m1, "user 0011 taken over from SAT 0102", 30))
sk_next2 = P.next_link_key(sk_next, S1)
check("the three keys of the chain differ", len({sk, sk_next, sk_next2}) == 3)
ue._run = False
time.sleep(0.5)
ue = Terminal(SimModem(sat1, "USER1"), ADDR_USER1, TC_VC_USER1, scid=S1, name="USER1", show_hk=False,
              show_relay=False).start()
end = time.time() + 25
while ue.hk is None and time.time() < end:
    time.sleep(0.2)
check("user hears SAT-1 after the second retuning", ue.hk is not None and ue.init_cop())
ue.sdls_start(sk_next2)
ok = ue.send_message(ADDR_GS, "after second handover")
end = time.time() + 40
while ok and time.time() < end and not any("after second handover" in m["text"] for m in gs.inbox):
    time.sleep(0.3)
check("protected message delivered after the second hand over under the second derived key",
      any("after second handover" in m["text"] for m in gs.inbox))
print(f"   second hand over, order to delivered message: {time.time() - t5:.1f} s")

for s in (sat1, sat2, sat3):
    print(f"{s.name} ISL lines:")
    for l in s.log:
        if "ISL" in l:
            print("   ", l)
gs._run = ue._run = False
for s in (sat1, sat2, sat3):
    s.close()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

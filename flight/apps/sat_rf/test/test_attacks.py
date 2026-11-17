"""Adversary node against the real satellite code over the emulated link.

A third terminal shares the air with the user and the ground station.  It can
receive every frame, and it can transmit on any telecommand virtual channel with
the COP-1 sequence number it has observed, which is what an attacker with a
radio can do.  Reference mode so the runs are short; the cryptographic checks are
identical in full mode.

    A1  replay: a captured MSG1 sent again inside the freshness window
    A2  injection: a MSG3 with one bit flipped in the ground station's signature,
        sent on the ground station's channel while a handshake is in progress;
        the live handshake must survive and complete with the genuine MSG3
    A3  stale: a MSG1 with a timestamp older than the freshness window
    A4  junk: an MSG1 shaped message with a bad signature during a live handshake;
        the live handshake must survive

Evidence is the satellite's own log lines and the outcome of the handshake.
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
import pqsat_proto as P                                                            # noqa: E402
from handshake_runner import load_bundle, ID_SAT, ID_GS, ID_UE                    # noqa: E402
from pqsat_roles import UserSession, GroundSession, HandshakeFailed               # noqa: E402

os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
os.environ["SAT_NO_SDLS"] = "1"          # this test exercises the handshake layer alone; SDLS has its own test

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


def satlog_since(mark):
    return sat.log[mark:]


def has(lines, text):
    return any(text in l for l in lines)


sat = SimSatellite(os.path.join(HERE, "satsim"), loss=0.0, debug=False)
gs = Terminal(SimModem(sat, "GS"), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
ue = Terminal(SimModem(sat, "USER1"), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
              show_relay=False).start()
# the adversary: one radio, retuned to whichever channel it attacks
adv_ue = Terminal(SimModem(sat, "ADV"), ADDR_USER1, TC_VC_USER1, name="ADV-as-user", show_hk=False,
                  show_relay=False).start()
adv_gs = Terminal(SimModem(sat, "ADV"), ADDR_GS, TC_VC_GROUND, name="ADV-as-ground", show_hk=False,
                  show_relay=False).start()

end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("link up", gs.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK")

b_ue, b_gs, b_sat = load_bundle("ue1"), load_bundle("gs"), load_bundle("sat1")


def sessions():
    u, g = UserSession(b_ue, full_certs=False), GroundSession(b_gs, full_certs=False)
    u.cache[ID_SAT], u.cache[ID_GS] = b_sat["cert"], b_gs["cert"]
    g.cache[ID_SAT], g.cache[ID_UE] = b_sat["cert"], b_ue["cert"]
    return u, g


def recv(term, types, timeout=200):
    end = time.time() + timeout
    while time.time() < end:
        r = term.wait_auth(min(5.0, end - time.time()))
        if r and r[1][1] in types:
            return r[1]
    return None


def complete_from_msg3(u, g, msg3):
    """Ground sends MSG3, then the handshake runs to the end.  Returns keys agree."""
    check("genuine MSG3 acknowledged", gs.send_auth(ID_SAT, msg3))
    m4 = recv(ue, (P.MSG4,))
    check("MSG4 reached the user", m4 is not None)
    if m4 is None:
        return False
    ue.send_auth(ID_SAT, u.handle(m4)[0][1])
    m6 = recv(gs, (P.MSG6,))
    gs.send_auth(ID_SAT, g.handle(m6)[0][1])
    m7 = recv(ue, (P.MSG7_FWD,))
    ue.send_auth(ID_SAT, u.handle(m7)[0][1])
    m8 = recv(gs, (P.MSG8_FWD,))                   # the ground receives MSG8 forwarded with the satellite's tag_s
    check("genuine MSG8 (forwarded with tag_s) reached the ground", m8 is not None)
    if m8 is None:
        return False
    g.handle(m8)
    return u.sk is not None and u.sk == g.sk


# ---------------------------------------------------------------- A2 and A4: injection during a live handshake
print("\n--- A2 forged MSG3 and A4 junk MSG1 during a live handshake ---")
u, g = sessions()
msg1 = u.start(ID_SAT, ID_GS)[0][1]
captured_msg1 = bytes(msg1)                       # the adversary records this off the air
check("MSG1 acknowledged", ue.send_auth(ID_SAT, msg1))
m2 = recv(gs, (P.MSG2,))
check("MSG2 reached the ground", m2 is not None)
msg3 = g.handle(m2)[0][1]

mark = len(sat.log)
# A4: junk MSG1 from the adversary on the user's channel (valid shape, bad signature)
junk = bytearray(captured_msg1)
junk[8 + 35 + 1088 + 1184] ^= 0x01                      # first octet of the user's nonce (after c_us and epk_u): a new nonce, a signature that no longer fits
adv_ue.vs = ue.vs                                 # the observed COP-1 sequence number
check("A4 junk MSG1 accepted by COP-1 (link layer cannot tell)", adv_ue.send_auth(ID_SAT, bytes(junk)))
ue.vs = adv_ue.vs
time.sleep(3)
lines = satlog_since(mark)
check("A4 junk MSG1 rejected by the satellite  [user signature rejected]", has(lines, "user signature rejected"))

mark = len(sat.log)
# A2: forged MSG3 on the ground station's channel
forged = bytearray(msg3)
forged[-100] ^= 0x01                              # inside the ML-DSA half of the ground station's signature
adv_gs.vs = gs.vs
check("A2 forged MSG3 accepted by COP-1 (link layer cannot tell)", adv_gs.send_auth(ID_SAT, bytes(forged)))
gs.vs = adv_gs.vs
time.sleep(3)
lines = satlog_since(mark)
check("A2 forged MSG3 rejected by the satellite  [ground station signature rejected]",
      has(lines, "ground station signature rejected"))
check("A2 no MSG4 produced for the forgery", not has(lines, "MSG4 to user"))

# the genuine handshake must still be alive
agree = complete_from_msg3(u, g, msg3)
check("live handshake survived both injections and completed, keys agree", agree)

# ---------------------------------------------------------------- A1: replay inside the window
print("\n--- A1 replay of the captured MSG1 ---")
mark = len(sat.log)
adv_ue.vs = ue.vs
check("A1 replayed MSG1 accepted by COP-1", adv_ue.send_auth(ID_SAT, captured_msg1))
ue.vs = adv_ue.vs
time.sleep(3)
lines = satlog_since(mark)
check("A1 replay rejected by the satellite  [replayed MSG1]", has(lines, "replayed MSG1"))
check("A1 no MSG2 produced for the replay", not has(lines, "MSG2 to ground"))
m2 = recv(gs, (P.MSG2,), timeout=15)
check("A1 ground saw no MSG2", m2 is None)

# ---------------------------------------------------------------- A3: stale MSG1
print("\n--- A3 MSG1 older than the freshness window ---")
u2, _ = sessions()
u2.clock = lambda: int(time.time()) - 2 * P.FRESHNESS_S
old = u2.start(ID_SAT, ID_GS)[0][1]
mark = len(sat.log)
check("A3 stale MSG1 acknowledged by COP-1", ue.send_auth(ID_SAT, old))
time.sleep(3)
lines = satlog_since(mark)
check("A3 stale MSG1 rejected by the satellite  [stale timestamp]", has(lines, "stale timestamp"))

print("\nsatellite log, attack related lines:")
for l in sat.log:
    if "rejected" in l or "replayed" in l or "stale" in l or "failed" in l:
        print("   SAT:", l)

gs._run = ue._run = adv_ue._run = adv_gs._run = False
sat.close()
print(f"\n{sum(r for _, r in results)}/{len(results)} checks passed")
sys.exit(0 if all(r for _, r in results) else 1)

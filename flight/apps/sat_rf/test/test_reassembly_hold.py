"""Attack class: denial of service through incomplete segmented telecommands.

The adversary has a radio on the user's uplink channel and has heard the COP-1 sequence
number.  It sends the first segment of a large telecommand and never the last one.

    R1  one first segment: the satellite holds the reassembly state and frees it by its
        inactivity timer (30 s); the hold time is measured
    R2  first segments repeated faster than the timer: the state never times out but it is one
        buffer per virtual channel, so nothing grows; the ground's channel is not affected
    R3  the genuine user's next telecommand is delivered: a new first segment replaces the
        state the adversary held
    R4  on the protected link the adversary's segment makes no reassembly state at all
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, CMD_PING  # noqa: E402
from sim_link import SimSatellite, SimModem                                                  # noqa: E402

os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
SEG_FIRST = 1
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def count(mark, text):
    return sum(text in l for l in sat.log[mark:])


def wait(mark, text, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if count(mark, text):
            return True
        time.sleep(0.2)
    return False


sat = SimSatellite(os.path.join(HERE, "satsim"))
gs = Terminal(SimModem(sat, "GS"), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False, show_relay=False).start()
ue = Terminal(SimModem(sat, "USER1"), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False, show_relay=False).start()
adv = Terminal(SimModem(sat, "ADV"), ADDR_USER1, TC_VC_USER1, name="ADV", show_hk=False, show_relay=False).start()
end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("link up, COP-1, clock", gs.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK")
check("genuine user message delivered before the attack", ue.send_message(ADDR_GS, "before"))

print("\n--- R1 one first segment, never finished ---")
adv.vs = ue.vs
m = len(sat.log)
t0 = time.time()
sent = adv._send_ad_segment(SEG_FIRST, os.urandom(200))
check("the link layer accepts the adversary's first segment (clear link, sequence number overheard)", sent)
freed = wait(m, "incomplete telecommand timed out, discarded", 45)
hold = time.time() - t0
check("the satellite frees the state by its inactivity timer", freed and 28 <= hold <= 36, f"held {hold:.1f} s")

print("\n--- R2 first segments repeated every 8 s for 48 s ---")
m = len(sat.log)
t0 = time.time()
n_sent = 0
pings = []
while time.time() - t0 < 48:
    n_sent += 1 if adv._send_ad_segment(SEG_FIRST, os.urandom(200)) else 0
    pings.append(gs.command(CMD_PING) == "OK")
    time.sleep(max(0, 8 - (time.time() - t0) % 8))
check("the state is held for the whole attack (no timeout fires while segments keep coming)",
      n_sent >= 5 and count(m, "incomplete telecommand timed out") == 0, f"{n_sent} first segments")
check("the ground station's commands are executed all the time: one buffer per virtual channel",
      all(pings) and len(pings) >= 5, f"{sum(pings)} of {len(pings)} PING acknowledged")
check("the satellite reports no reassembly overflow and keeps sending housekeeping",
      count(m, "exceeds the reassembly limit") == 0 and gs.hk is not None)

print("\n--- R3 the genuine user after the attack ---")
ue.vs = adv.vs                               # the user follows the sequence number in the CLCW
m = len(sat.log)
check("the user's next message is delivered while the adversary's state is still held", ue.send_message(ADDR_GS, "after"))
check("it replaced the held state: no stale segment was joined to it", count(m, "continuing segment with no first segment") == 0)
wait(m, "incomplete telecommand timed out", 1)

print("\n--- R4 the same on the protected link ---")
sk = os.urandom(32)
sat.sdls_start(sk)
ue.sdls_start(sk)
time.sleep(2)
check("protected user message delivered", ue.send_message(ADDR_GS, "protected"))
adv.vs = ue.vs
m = len(sat.log)
adv._send_ad_segment(SEG_FIRST, os.urandom(200), tries=2)
time.sleep(34)
check("the adversary's clear first segment is rejected and makes no reassembly state",
      count(m, "incomplete telecommand timed out") == 0, next((l for l in sat.log[m:] if "SDLS" in l or "reject" in l), "no rejection line"))
ue.init_cop()
check("the protected user link still works", ue.send_message(ADDR_GS, "still protected"))

sat.close()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

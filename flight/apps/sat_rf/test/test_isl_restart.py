"""Restart of the inter satellite association: can a key and IV pair repeat, and are frames
recorded before a restart accepted after it?  Two instances of the flight core, emulated ISL.

The ISL association is keyed from the pairwise key K_ISL that the registry provisions as a
key file.  The IV of a frame is a 4 octet salt derived from K_ISL followed by an 8 octet
frame counter.  The counter starts again when the flight software starts.

  A. restart with the SAME key file (what the measured runs of the paper did):
       the frames sent after the restart reuse the IVs of the frames before it, and
       frames recorded before the restart are accepted again by the restarted receiver
  B. restart with a NEW key file each time (the registry writes 32 new random octets, as
     its provisioning step does), RESTARTS times:
       every restart has a new key fingerprint, the frame counter starts at one, no key
       and IV pair repeats, and every frame recorded before the restart is rejected

    RESTARTS=5 FRAMES=10 python3 test_isl_restart.py
"""
import hashlib
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
import ccsds_link                                                           # noqa: E402
SF = int(os.environ.get("SF", "7"))                                         # only shortens the ground link air time
ccsds_link.lora_airtime_ms.__defaults__ = (SF, 125e3, 3, 8)
from ccsds_link import Terminal, ADDR_GS, TC_VC_GROUND, CMD_PING, lora_airtime_ms   # noqa: E402
from sim_link import SimSatellite, SimModem                                 # noqa: E402

KEYS = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_DIR"] = KEYS
EXE = os.path.join(HERE, os.environ.get("SATSIM", "satsim"))
RESTARTS = int(os.environ.get("RESTARTS", "5"))
FRAMES = int(os.environ.get("FRAMES", "10"))
S1, S2 = 0x101, 0x102
work = tempfile.mkdtemp(prefix="isl_restart_")
results, record = [], dict(restarts=RESTARTS, frames_per_generation=FRAMES, A={}, B=[])


def check(name, cond, note=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{note}]" if note else ""), flush=True)


def new_key(tag):
    """What the registry does when it provisions a pairwise key: 32 random octets in a key file."""
    p = os.path.join(work, f"isl_sat1_sat2_{tag}.key")
    with open(p, "wb") as f:
        f.write(os.urandom(32))
    return p


def fp(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def iv_of(frame):
    return frame[8:20]                       # TM primary header 6 | SPI 2 | IV 12 (salt 4 | counter 8)


def counter(frame):
    return int.from_bytes(frame[12:20], "big")


class Generation:
    """One life of the two flight instances between two restarts."""

    def __init__(self, keyfile):
        win = str(int(lora_airtime_ms(255)) + 800)
        e1 = dict(SAT_SCID=hex(S1), SAT_ISL_PEER=hex(S2), SAT_ISL_KEY=keyfile, SAT_RX_WINDOW_MS=win, SAT_LORA_SF=str(SF))
        e2 = dict(e1, SAT_SCID=hex(S2), SAT_ISL_PEER=hex(S1), SAT_GS_VIA_ISL="1")
        self.s1 = SimSatellite(EXE, debug=False, env=e1, name="SAT-1")
        self.s2 = SimSatellite(EXE, debug=False, env=e2, name="SAT-2")
        self.s1.isl_peer, self.s2.isl_peer = self.s2, self.s1
        self.gs = Terminal(SimModem(self.s1, "GS"), ADDR_GS, TC_VC_GROUND, scid=S1, name="GS", show_hk=False).start()
        end = time.time() + 25
        while self.gs.hk is None and time.time() < end:
            time.sleep(0.2)
        self.ok = self.gs.hk is not None and self.gs.init_cop() and self.gs.set_time() == "OK"

    def traffic(self, n):
        """n forwarded commands: each is one protected ISL frame from SAT-1 to SAT-2."""
        before = len(self.s1.isl_log)
        ok = sum(self.gs.forward_command(S2, CMD_PING) == "OK" for _ in range(n))
        time.sleep(1.0)
        return ok, [f for _, f in self.s1.isl_log[before:]]

    def replay(self, frames):
        """Send recorded SAT-1 frames into SAT-2 again.  Returns (rejected, executed)."""
        mark = len(self.s2.log)
        for f in frames:
            self.s2.isl_rx(f)
            time.sleep(0.15)
        time.sleep(1.5)
        new = self.s2.log[mark:]
        return sum("rejected by SDLS" in l for l in new), sum("forwarded command" in l and "executed" in l for l in new)

    def close(self):
        for t in (self.gs, self.s1, self.s2):
            try:
                t.close()
            except Exception:
                pass


print(f"satellite {os.path.basename(EXE)}, {FRAMES} protected ISL frames per generation")

print("\n=== A. restart with the same key file ===")
key = new_key("A")
g = Generation(key)
check("constellation up", g.ok)
n_ok, before = g.traffic(FRAMES)
check("forwarded commands executed over the protected ISL", n_ok == FRAMES and len(before) >= FRAMES, f"{n_ok} of {FRAMES}, {len(before)} frames recorded")
g.close()
time.sleep(1)
g = Generation(key)                                    # the restart: same key file
check("constellation up after the restart", g.ok)
rej, exe = g.replay(before)                            # frames recorded before the restart, sent again
n_ok, after = g.traffic(FRAMES)
reused = len({iv_of(f) for f in before} & {iv_of(f) for f in after})
print(f"   frames recorded before the restart and replayed after it: {len(before) - rej} of {len(before)} accepted "
      f"({exe} forwarded commands executed again), {rej} rejected")
print(f"   IVs used again under the same key after the restart: {reused} of {len(after)}; first counter after the restart: {counter(after[0])}")
check("A. with the same key the IVs repeat after a restart", reused > 0, f"{reused} of {len(after)}")
check("A. with the same key recorded frames are accepted again after a restart", rej < len(before), f"{len(before) - rej} of {len(before)} accepted")
record["A"] = dict(key_fingerprint=fp(key), recorded=len(before), replay_rejected=rej, replay_accepted=len(before) - rej, commands_executed_again=exe,
                   ivs_reused=reused, frames_after=len(after), first_counter_after=counter(after[0]))
g.close()

print(f"\n=== B. a new key file at every restart, {RESTARTS} restarts ===")
key = new_key("B0")
g = Generation(key)
check("constellation up", g.ok)
n_ok, prev = g.traffic(FRAMES)
seen = {(fp(key), iv_of(f)) for f in prev}             # every (key, IV) pair used so far
fps = [fp(key)]
tot_rec = tot_rej = tot_exe = pairs_repeated = 0
for i in range(1, RESTARTS + 1):
    g.close()
    time.sleep(1)
    key = new_key(f"B{i}")                             # the registry writes a new key before the restart
    g = Generation(key)
    rej, exe = g.replay(prev)
    n_ok, cur = g.traffic(FRAMES)
    pairs = {(fp(key), iv_of(f)) for f in cur}
    rep = len(pairs & seen)
    seen |= pairs
    fps.append(fp(key))
    tot_rec += len(prev); tot_rej += rej; tot_exe += exe; pairs_repeated += rep
    print(f"   restart {i}: key fingerprint {fp(key)}, first frame counter {counter(cur[0])}, "
          f"{rej} of {len(prev)} recorded frames rejected, {exe} executed, {n_ok} of {FRAMES} new commands executed, key and IV pairs repeated {rep}")
    record["B"].append(dict(restart=i, up=bool(g.ok), key_fingerprint=fp(key), first_counter=counter(cur[0]), recorded=len(prev), replay_rejected=rej,
                            commands_executed_again=exe, new_commands_ok=n_ok, pairs_repeated=rep))
    check(f"B. restart {i}: link up and new traffic accepted", g.ok and n_ok == FRAMES)
    prev = cur
g.close()
check("B. every restart has a new key fingerprint", len(set(fps)) == RESTARTS + 1)
check("B. the frame counter starts at one after every restart", all(r["first_counter"] == 1 for r in record["B"]))
check("B. every frame recorded before a restart is rejected after it", tot_rej == tot_rec and tot_exe == 0, f"{tot_rej} of {tot_rec}")
check("B. no key and IV pair repeats", pairs_repeated == 0, f"{len(seen)} pairs")
record["B_total"] = dict(recorded=tot_rec, rejected=tot_rej, executed=tot_exe, pairs=len(seen), pairs_repeated=pairs_repeated, fingerprints=fps)
json.dump(record, open(os.path.join(HERE, "isl_restart.json"), "w"), indent=1)
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

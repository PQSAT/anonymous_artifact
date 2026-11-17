"""Interoperability: Python user and ground station against the C satellite.

This is the check that the flight software implementation and the ground
software agree octet for octet, for both certificate modes, including the
demand path.  No link in between; that comes next.
"""
import os
import pickle
import subprocess
import sys
import time

import pqsat_proto as P
from pqsat_roles import UserSession, GroundSession, HandshakeFailed

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(HERE, "keys")
ID_GS, ID_UE, ID_SAT = 0x0001, 0x0011, 0x0101
fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name, flush=True)
    fails += 0 if cond else 1


class CSatellite:
    def __init__(self, mode="full", preload_user=False):
        args = [os.path.join(HERE, "authsim"), os.path.join(KEYS, "sat1.bundle"), os.path.join(KEYS, "gs.cert"),
                mode] + ([os.path.join(KEYS, "ue1.cert")] if preload_user else [])
        self.p = subprocess.Popen(args,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.logs = []
        self._read_until_ok(first=True)

    def _read_until_ok(self, first=False):
        out = []
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("satellite exited")
            line = line.rstrip("\n")
            if line.startswith("LOG,"):
                self.logs.append(line[4:])
                if first:
                    return out
                continue
            if line == "OK":
                return out
            if line.startswith("S,"):
                _, dst, hexm = line.split(",", 2)
                out.append((int(dst, 16), bytes.fromhex(hexm)))
            else:
                out.append(("raw", line))

    def handle(self, from_id, msg, now=None):
        now = int(time.time()) if now is None else now
        self.p.stdin.write(f"M,{from_id:04X},{now},{msg.hex().upper()}\n")
        self.p.stdin.flush()
        return self._read_until_ok()

    def finish(self):
        self.p.stdin.write("Q\n")
        self.p.stdin.flush()
        stat, sk = None, None
        for line in self.p.stdout:
            line = line.strip()
            if line.startswith("STAT,"):
                stat = dict(kv.split("=") for kv in line[5:].split(","))
            elif line.startswith("SK,"):
                sk = bytes.fromhex(line[3:])
        self.p.wait()
        return stat, sk


def load(name):
    with open(os.path.join(KEYS, name + ".pickle"), "rb") as f:
        return pickle.load(f)


def run(mode="full", preload=True, tamper=None):
    """Drive the three parties.  Returns (ue, gs, sat_sk, sat_stat, trace)."""
    b_ue, b_gs, b_sat = load("ue1"), load("gs"), load("sat1")
    full = (mode == "full")
    ue, gs = UserSession(b_ue, full_certs=full), GroundSession(b_gs, full_certs=full)
    ue.cache[ID_SAT] = b_sat["cert"]
    if preload:
        ue.cache[ID_GS] = b_gs["cert"]
        gs.cache[ID_SAT] = b_sat["cert"]
        gs.cache[ID_UE] = b_ue["cert"]
    sat = CSatellite(mode, preload_user=preload)
    trace = []
    queue = [("ue", "sat", b) for _, b in ue.start(ID_SAT, ID_GS)]
    step = 0
    while queue:
        src, dst, b = queue.pop(0)
        step += 1
        trace.append((src, dst, b[1], len(b)))
        if tamper and tamper[0] == step:
            b = bytearray(b); b[tamper[1]] ^= 1; b = bytes(b)
        if dst == "sat":
            from_id = ID_UE if src == "ue" else ID_GS
            for dst_id, m in sat.handle(from_id, b):
                queue.append(("sat", "ue" if dst_id == ID_UE else "gs", m))
        elif dst == "ue":
            queue.extend(("ue", d, m) for d, m in ue.handle(b))
        else:
            queue.extend(("gs", d, m) for d, m in gs.handle(b))
    stat, sat_sk = sat.finish()
    return ue, gs, sat_sk, stat, trace, sat.logs


# ---- full certificates ----
ue, gs, sk, stat, trace, logs = run("full")
check("full mode: C satellite completes the handshake", stat["ok"] == "1" and stat["failed"] == "0")
check("full mode: Python user, Python ground and C satellite share one key",
      ue.sk is not None and ue.sk == gs.sk == sk)
sizes = {t: n for _, _, t, n in trace}
check("full mode: MSG2 from C is 26550 octets", sizes.get(P.MSG2) == 26550)
check("full mode: MSG4 from C is 25334 octets", sizes.get(P.MSG4) == 25334)
print("   trace:", [(s, d, f"{t:#04x}", n) for s, d, t, n in trace])
print("   satellite timings us:", {k: v for k, v in stat.items() if k.endswith("_us")})

# ---- reference mode with everything preloaded ----
ue, gs, sk, stat, trace, logs = run("ref", preload=True)
check("reference mode: handshake completes", stat["ok"] == "1")
check("reference mode: one key on all three", ue.sk == gs.sk == sk and sk is not None)
sizes = {t: n for _, _, t, n in trace}
check("reference mode: MSG2 from C is 11402 octets", sizes.get(P.MSG2) == 11402)
check("reference mode: MSG4 from C is 10186 octets", sizes.get(P.MSG4) == 10186)

# ---- reference mode with nothing preloaded: demands must resolve it ----
ue, gs, sk, stat, trace, logs = run("ref", preload=False)
check("reference mode, cold caches: demands lead to a complete handshake",
      stat["ok"] == "1" and ue.sk == gs.sk == sk and sk is not None)
check("reference mode, cold caches: at least one demand was sent by C", int(stat["demands"]) >= 1)
print("   messages exchanged:", len(trace), " demands by satellite:", stat["demands"])

# ---- tamper: the C satellite must reject ----
def expect_reject(name, tamper):
    try:
        ue, gs, sk, stat, trace, logs = run("full", tamper=tamper)
        bad = [l for l in logs if "failed" in l or "rejected" in l]
        check(name + f"  [{bad[-1] if bad else 'no rejection logged'}]",
              (stat["failed"] == "1" or stat["rejected"] != "0") and sk is None)
    except HandshakeFailed as e:
        check(name + f"  [python side: {e.args[0]}]", True)

expect_reject("C rejects a flipped bit in the user's ML-DSA signature (MSG1)", (1, 13266 - 3341 + 7))
expect_reject("C rejects a flipped bit in the user's KEM tag (MSG1)", (1, 13266 - 4))
expect_reject("C rejects a flipped bit in the user's certificate (MSG1)", (1, 30))
expect_reject("C rejects a flipped bit in the ground station's signature (MSG3)", (3, 14252 - 4))
expect_reject("C rejects a flipped bit in a wrap from the ground (MSG7)", (7, 2 + 80 + 5))
expect_reject("C rejects a flipped bit in the ground confirmation tag (MSG7)", (7, 2 + 160 + 5))
ue, gs, sk, stat, trace, logs = run("full", tamper=(9, 2 + 5))
bad = [l for l in logs if "rejected" in l]
check("C rejects a flipped bit in the user's final confirmation (MSG8): nothing is forwarded and the ground "
      f"station does not finish  [{bad[-1] if bad else 'no rejection logged'}]",
      stat["rejected"] != "0" and gs.state != "done" and not any(t[2] == "0x0b" for t in trace))
expect_reject("the user rejects a flipped bit in the satellite confirmation tag_s from C (MSG7f)", (8, 2 + 80 + 32 + 5))
expect_reject("the ground station rejects a flipped bit in tag_s as forwarded by C (MSG8 forwarded)", (10, 2 + 32 + 5))
expect_reject("C rejects a flipped bit in the user's ephemeral key (MSG1)", (1, 2 + 6 + 7609 + 1088 + 50))
expect_reject("C rejects a flipped bit in e_gs (MSG3)", (3, 2 + 7609 + 1088 + 50))
expect_reject("C rejects a flipped bit in e_gu (MSG3)", (3, 2 + 7609 + 2176 + 50))

print(f"\n{'ALL PASSED' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)

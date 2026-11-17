#!/usr/bin/env python3
"""Run the twelve attack classes and report one row per class.

This drives the attack evidence that needs no bench: the protocol layer suite (Python roles
and the flight C satellite, no link) and the emulator link tests (the flight core over the
simulated radio). Each class is shown succeeding against the unprotected baseline inside its
test and failing against the protected system; this runner reports the protected outcome per
class and writes attacks_report.json and attacks_report.csv next to itself.

    python run_attacks.py              run every class that runs without the bench
    python run_attacks.py --list       print the catalogue and the per class route, run nothing
    python run_attacks.py --only 4 5   run only these class numbers

Two classes also have an over the air form that needs the adversary radio on the bench
(reassembly hold and air time exhaustion). Their software and emulator evidence runs here;
the over the air commands are in README.md section "On the air".
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, ".."))
PQC = os.path.join(REL, "protocol")
EMU = os.path.join(REL, "flight", "apps", "sat_rf", "test")

# class number: (key, one line, test file, folder, phase tag shown in that test)
CLASSES = {
    1:  ("replay_handshake",         "a captured MSG1 sent again is refused by the freshness check",
         "test_attacks.py", EMU, "A1"),
    2:  ("forged_message",           "a forged MSG3 with valid framing fails the signature",
         "test_attacks.py", EMU, "A2"),
    3:  ("bit_flip",                 "a bit flipped in flight is caught by the SDLS tag and the signature",
         "test_attacks.py", EMU, "A3"),
    4:  ("mitm_relay",               "the relay role carries frames but learns no session key",
         "test_attacks_protocol.py", PQC, "B1"),
    5:  ("downgrade",                "a handshake relabelled to an older version is rejected",
         "test_attacks_protocol.py", PQC, "B2"),
    6:  ("reassembly_hold",          "a held first segment is freed by the timer, one buffer per channel",
         "test_reassembly_hold.py", EMU, "R"),
    7:  ("window_vs_segments",       "a replayed inter satellite frame is dropped by the anti replay window",
         "test_isl_attacks.py", EMU, "I1"),
    8:  ("airtime_exhaustion",       "junk MSG1 on the slow link wastes air time but authenticates nothing",
         "test_attacks.py", EMU, "A4"),
    9:  ("replayed_handover",        "a recorded hand over transfer sent again is refused as a replay",
         "test_isl_key_compromise.py", EMU, "K3"),
    10: ("revocation_suppression",   "a suppressed or forged revocation list changes nothing; a revoked id is refused",
         "test_attacks_protocol.py", PQC, "B4"),
    11: ("compromised_isl_key",      "one pairwise inter satellite key reads its link but yields no session key; stays on its hop",
         "test_isl_key_compromise.py", EMU, "K"),
    12: ("session_state_corruption", "forward secrecy holds; leaked long term keys open no past session",
         "test_attacks_protocol.py", PQC, "B3"),
}
BENCH = {6, 8}            # also have an over the air form (adversary radio); see README


def passed(out):
    """True when a test's final tally line reports every check passing."""
    tally = [l for l in out.splitlines() if "checks passed" in l or "ALL PASSED" in l]
    if not tally:
        return None
    last = tally[-1]
    if "ALL PASSED" in last:
        return True
    try:
        a, b = last.split("/")[0].strip().split()[-1], last.split("/")[1].split()[0]
        return a == b
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", type=int, nargs="+", default=None)
    ap.add_argument("--python", default=sys.executable)
    a = ap.parse_args()

    if a.list:
        print(f"{'#':>2}  {'class':24s}  {'test':28s}  shows")
        for n, (key, line, test, _, _) in CLASSES.items():
            air = "  (+ over the air)" if n in BENCH else ""
            print(f"{n:2d}  {key:24s}  {test:28s}  {line}{air}")
        return 0

    pick = a.only or list(CLASSES)
    files = {}                                  # run each unique test once
    for n in pick:
        _, _, test, cwd, _ = CLASSES[n]
        files.setdefault((test, cwd), None)
    env = dict(os.environ, SAT_AUTH_DIR=os.path.join(PQC, "keys"), SAT_AUTH_REF="1", SAT_AUTH_PRELOAD_UE="1")
    for (test, cwd) in list(files):
        print(f"\n===== running {test} =====", flush=True)
        t0 = time.time()
        try:
            r = subprocess.run([a.python, test], cwd=cwd, env=env, capture_output=True, text=True, timeout=5400)
            out = r.stdout + r.stderr
        except Exception as e:                  # noqa: BLE001
            out = f"error: {e}"
        tail = [l for l in out.splitlines() if l.startswith(("PASS", "FAIL", "   ")) or "checks passed" in l or "ALL PASSED" in l]
        print("\n".join(tail[-6:]))
        files[(test, cwd)] = dict(ok=passed(out), seconds=round(time.time() - t0, 1), text=out)

    rows = []
    for n in pick:
        key, line, test, cwd, tag = CLASSES[n]
        res = files[(test, cwd)]
        ok = res["ok"]
        rows.append(dict(cls=n, key=key, shows=line, test=test, phase=tag,
                         outcome="rejected" if ok else ("FAILED" if ok is False else "no result"),
                         over_the_air=n in BENCH))

    print("\n" + "=" * 78)
    print(f"{'#':>2}  {'class':24s}  {'outcome':9s}  evidence")
    for r in rows:
        air = "  + bench" if r["over_the_air"] else ""
        print(f"{r['cls']:2d}  {r['key']:24s}  {r['outcome']:9s}  {r['test']} {r['phase']}{air}")
    good = [r for r in rows if r["outcome"] == "rejected"]
    print(f"\n{len(good)} of {len(rows)} classes: the protected system rejected the attack.")
    if len(good) != len(rows):
        print("classes not rejected (look at the test output above):",
              ", ".join(str(r["cls"]) for r in rows if r["outcome"] != "rejected"))

    rep = dict(when=time.strftime("%Y-%m-%d %H:%M:%S"), classes=len(CLASSES), run=len(rows),
               rejected=len(good), rows=rows)
    with open(os.path.join(HERE, "attacks_report.json"), "w") as f:
        json.dump(rep, f, indent=1)
    with open(os.path.join(HERE, "attacks_report.csv"), "w") as f:
        f.write("class,key,outcome,test,phase,over_the_air\n")
        for r in rows:
            f.write(f"{r['cls']},{r['key']},{r['outcome']},{r['test']},{r['phase']},{r['over_the_air']}\n")
    print("\nreport -> attacks_report.json and attacks_report.csv")
    return 0 if len(good) == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())

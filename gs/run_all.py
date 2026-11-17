#!/usr/bin/env python3
"""run_all.py  run the experiments one after another, unattended, and keep every output.

The bridge must already be running in another window. Nothing else may hold the COM ports.

    python run_all.py --gs COM4 --ue COM8 --runs 10
    python run_all.py --gs COM4 --ue COM5 --runs 20 --constellation
    python run_all.py --gs COM4 --ue COM8 --runs 10 --isl COM9,COM12,COM14,COM15
    python run_all.py --gs COM4 --ue COM8 --dry-run              show the plan, run nothing

Steps (each can be skipped with --skip, e.g. --skip selftest,revocation)
  protocol    protocol self test and protocol layer attack suite (no radio)
  selftest    ISL radio self test, three times (only with --isl; no Versal traffic)
  campaign    N handshakes over the radio (auth_campaign.py); from the second one on under SDLS
  revocation  revoke the user, show that a handshake is refused, reinstate, show that it works

Every step writes its full output to results_<date>_<time>/<step>.log and the summary to
summary.txt in the same folder. A failed step does not stop the following ones.
"""
import argparse
import datetime
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.dirname(HERE)
PY = sys.executable


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gs", required=True, help="ground station radio port")
    ap.add_argument("--ue", required=True, help="user terminal radio port")
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--mode", default="ref", choices=["ref", "full"])
    ap.add_argument("--constellation", action="store_true", help="user on SAT-2, ground on SAT-1")
    ap.add_argument("--isl", help="the four ISL radio ports: tx1,rx1,tx2,rx2")
    ap.add_argument("--skip", default="", help="comma separated steps to leave out")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    skip = {s.strip() for s in a.skip.split(",") if s.strip()}
    out = os.path.join(HERE, "results_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    camp = [PY, "auth_campaign.py", "--gs", a.gs, "--ue", a.ue, "--mode", a.mode] + (["--constellation"] if a.constellation else [])
    sat = "0x102" if a.constellation else "0x101"
    steps = []
    if "protocol" not in skip:
        steps += [("protocol_selftest", os.path.join(REL, "protocol"), [PY, "test_handshake.py"], 900, True),
                  ("protocol_attacks", os.path.join(REL, "protocol"), [PY, "test_attacks_protocol.py"], 1800, True)]
    if a.isl and "selftest" not in skip:
        p = a.isl.split(",")
        if len(p) != 4:
            ap.error("--isl needs four ports: tx1,rx1,tx2,rx2")
        for i in (1, 2, 3):
            steps.append((f"isl_selftest_{i}", os.path.join(REL, "bridge"),
                          [PY, "sat_bridge.py", "--isl-selftest", "--isl1-tx", p[0], "--isl1-rx", p[1],
                           "--isl2-tx", p[2], "--isl2-rx", p[3]], 300, True))
    if "campaign" not in skip:
        steps.append(("campaign", HERE, camp + ["--runs", str(a.runs)], a.runs * 1500 + 600, True))
    if "revocation" not in skip:
        steps += [("revocation_1_revoke_user", HERE, [PY, "send_crl.py", "--revoke", "0x0011", "--port", a.gs, "--sat", sat], 600, True),
                  # the satellite refuses MSG1 at once; the terminal would wait for MSG2 until its own timeout,
                  # so the step is stopped after MSG1 has had time to go up and MSG2 to start
                  ("revocation_2_handshake_must_fail", HERE, camp + ["--runs", "1"], 300 if a.mode == "ref" else 480, False),
                  ("revocation_3_reinstate", HERE, [PY, "send_crl.py", "--revoke", "none", "--port", a.gs, "--sat", sat], 600, True),
                  ("revocation_4_handshake_must_work", HERE, camp + ["--runs", "1"], 1500, True)]

    print(f"{len(steps)} steps, results in {out}")
    for name, cwd, cmd, limit, _ in steps:
        print(f"  {name:34s} {' '.join(cmd[1:])}")
    if a.dry_run:
        return 0
    os.makedirs(out)
    summary = []
    for name, cwd, cmd, limit, want_ok in steps:
        t0 = time.time()
        print(f"\n===== {name}  ({datetime.datetime.now():%H:%M:%S}) =====", flush=True)
        log = os.path.join(out, name + ".log")
        tail = []
        try:
            with open(log, "w", encoding="utf-8", errors="replace") as f:
                p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                     errors="replace", bufsize=1)
                timer = threading.Timer(limit, p.kill)      # a step that hangs is stopped at its time limit
                timer.start()
                for line in p.stdout:
                    f.write(line); f.flush()
                    sys.stdout.write(line); sys.stdout.flush()
                    tail = (tail + [line.rstrip()])[-400:]
                p.wait()
                timer.cancel()
                rc = p.returncode
                if time.time() - t0 >= limit:
                    tail.append(f"stopped at the time limit of {limit} s")
                    f.write(tail[-1] + "\n")
        except Exception as e:                      # a step that cannot start must not stop the rest
            rc, tail = -1, [f"could not run: {e}"]
        text = "\n".join(tail)
        # a handshake counts as completed only if the campaign says so
        done = "keys agree: True" in text if cmd[1] == "auth_campaign.py" else rc == 0
        ok = done if want_ok else not done
        key = [l for l in tail if any(k in l for k in ("mean ", "checks passed", "ALL PASSED", "SELFTEST", "keys agree",
                                                      "uplink to SAT", "of 20 frames", "completed"))][-4:]
        summary.append((name, "OK" if ok else "CHECK", time.time() - t0, key))
        print(f"----- {name}: {'OK' if ok else 'CHECK'} in {time.time() - t0:.0f} s", flush=True)
        time.sleep(5)                               # let the radios and COP-1 settle between steps
    # campaign records and bridge logs next to the step logs
    for f in os.listdir(HERE):
        if f.startswith("auth_hw_") and f.endswith(".json") and os.path.getmtime(os.path.join(HERE, f)) > time.time() - 86400:
            shutil.copy2(os.path.join(HERE, f), out)
    for f in os.listdir(os.path.join(REL, "bridge")):
        if f.endswith(".csv"):
            shutil.copy2(os.path.join(REL, "bridge", f), out)
    with open(os.path.join(out, "summary.txt"), "w", encoding="utf-8") as f:
        for name, st, secs, key in summary:
            f.write(f"{st:6s} {name:34s} {secs:7.0f} s\n")
            for k in key:
                f.write(f"         {k}\n")
    print("\n" + open(os.path.join(out, "summary.txt"), encoding="utf-8").read())
    print("everything is in", out)
    return 0 if all(s[1] == "OK" for s in summary) else 1


if __name__ == "__main__":
    sys.exit(main())

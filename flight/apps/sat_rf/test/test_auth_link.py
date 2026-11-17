"""The three party handshake over the emulated link.

Real code: the C satellite core with the authentication module, as a process;
the Python user and ground station over ccsds_link with segmentation and
spanning; COP-1 on every uplink segment.  Simulated: the radio channel.

    python3 test_auth_link.py                 clean channel, full certificates
    MODE=ref python3 test_auth_link.py        certificate references
    LOSS=0.1 python3 test_auth_link.py        10 percent frame loss
    RUNS=5 python3 test_auth_link.py          repeat and report mean
"""
import json
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
MODE = os.environ.get("MODE", "full")
RUNS = int(os.environ.get("RUNS", "1"))

os.environ["SAT_AUTH_DIR"] = os.path.join(REL, "protocol", "keys")
if MODE == "ref":
    os.environ["SAT_AUTH_REF"] = "1"
    os.environ["SAT_AUTH_PRELOAD_UE"] = "1"

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name, flush=True)


sat = SimSatellite(os.path.join(HERE, "satsim"), loss=LOSS, debug=False)
gs = Terminal(SimModem(sat, "GS", loss=LOSS), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
ue = Terminal(SimModem(sat, "USER1", loss=LOSS), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
              show_relay=False).start()

end = time.time() + 25
while gs.hk is None and time.time() < end:
    time.sleep(0.2)
check("ground receives housekeeping", gs.hk is not None)
check("ground COP-1 initialised", gs.init_cop())
check("user COP-1 initialised", ue.init_cop())
check("satellite clock set", gs.set_time() == "OK")

runs = []
for i in range(RUNS):
    print(f"\n--- handshake {i + 1} of {RUNS}, mode {MODE}, loss {LOSS} ---")
    r = run_handshake(ue, gs, mode=MODE, preload=True)
    runs.append(r)
    check(f"handshake {i + 1}: completed with one session key on user and ground", r["ok"])

sat_logs = [l for l in getattr(sat, "logs", []) if "auth" in l]
if sat_logs:
    print("   satellite:", sat_logs[-1])

out = os.path.join(HERE, f"auth_{MODE}_loss{LOSS}.json")
with open(out, "w") as f:
    json.dump(runs, f, indent=1)
print(f"\nmean over {RUNS}: {sum(r['seconds'] for r in runs)/RUNS:.1f} s, "
      f"{sum(r['uplink_segments'] for r in runs)/RUNS:.0f} uplink segments, "
      f"{sum(r['downlink_frames'] for r in runs)/RUNS:.0f} downlink frames   -> {out}")

gs._run = ue._run = False
sat.close()
print(f"\n{sum(r for _, r in results)}/{len(results)} checks passed")
sys.exit(0 if all(r for _, r in results) else 1)

"""One pass of the PQSAT-8 model at another radio setting, on the emulated links.

The hardware pass run (SF9, 14 dBm) did not complete inside the pass.  This test repeats the
same experiment in emulation at a setting given on the command line:

    SF=7 PTX=22 RUNS=3 python3 test_pass_rate.py

Real code: two instances of the flight core set to that spreading factor (SAT_LORA_SF),
the terminal library, the protocol.  Emulated: the radio channels with the air time of the
setting, the ISL (12 ms per frame).  Modelled: the highest pass of the day at the user site,
applied to every frame of the user link (window, delay, loss from the link margin of the
setting: sensitivity of the spreading factor, transmit power PTX).

    user --(pass model)-- SAT-2 ==ISL== SAT-1 ---- ground station

  0. one handshake on the clean link at this setting, for the duration
  1..RUNS. a new constellation each time, the handshake centred on the peak of the pass
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "gs"))
sys.path.insert(0, os.path.join(REL, "protocol"))
SF = int(os.environ.get("SF", "7"))
PTX = float(os.environ.get("PTX", "22"))
RUNS = int(os.environ.get("RUNS", "3"))
START = os.environ.get("START", "center")     # center: centred on the peak; edge: at the start of the usable window
EXE = os.path.join(HERE, os.environ.get("SATSIM", "satsim"))

import ccsds_link                                                                   # noqa: E402
ccsds_link.lora_airtime_ms.__defaults__ = (SF, 125e3, 3, 8)                         # air time of the setting, everywhere
ccsds_link.lora_bitrate_bps.__defaults__ = (SF, 125e3, 3)
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, lora_airtime_ms, lora_bitrate_bps  # noqa: E402
from sim_link import SimSatellite, SimModem                                         # noqa: E402
from handshake_runner import run_handshake                                          # noqa: E402
from pqsat_roles import HandshakeFailed                                             # noqa: E402
from orbit_link import PassModel, ModelledLink                                      # noqa: E402
import linkbudget                                                                   # noqa: E402

KEYS = os.path.join(REL, "protocol", "keys")
os.environ["SAT_AUTH_DIR"] = KEYS
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
S1, S2 = 0x101, 0x102
_margin = linkbudget.margin_db
linkbudget.margin_db = lambda d, profile="SF9", **kw: _margin(d, f"SF{SF}", p_tx_dbm=PTX)   # margin of the setting

results, record = [], dict(sf=SF, ptx_dbm=PTX, bitrate_bps=round(lora_bitrate_bps()), air_255_ms=round(lora_airtime_ms(255)), runs=[])


def check(name, cond, note=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{note}]" if note else ""), flush=True)


def constellation(model):
    win = str(int(lora_airtime_ms(255)) + 800)
    env1 = dict(SAT_SCID=hex(S1), SAT_ISL_PEER=hex(S2), SAT_ISL_KEY=os.path.join(KEYS, "isl_sat1_sat2.key"), SAT_RX_WINDOW_MS=win, SAT_LORA_SF=str(SF))
    env2 = dict(env1, SAT_SCID=hex(S2), SAT_ISL_PEER=hex(S1), SAT_GS_VIA_ISL="1")
    s1 = SimSatellite(EXE, debug=False, env=env1, name="SAT-1")
    s2 = SimSatellite(EXE, debug=False, env=env2, name="SAT-2")
    s1.isl_peer, s2.isl_peer = s2, s1
    gs = Terminal(SimModem(s1, "GS"), ADDR_GS, TC_VC_GROUND, scid=S1, name="GS", show_hk=False).start()
    ulink = SimModem(s2, "USER1")
    if model is not None:
        ulink = ModelledLink(ulink, model)
    ue = Terminal(ulink, ADDR_USER1, TC_VC_USER1, scid=S2, name="USER1", show_hk=False, show_relay=False).start()
    end = time.time() + 25
    while (gs.hk is None or ue.hk is None) and time.time() < end:
        time.sleep(0.2)
    ok = gs.hk is not None and ue.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK"
    time.sleep(3)
    return s1, s2, gs, ue, ok


def close(*things):
    for t in things:
        for f in ("stop", "close"):
            try:
                getattr(t, f)()
            except Exception:
                pass


print(f"setting: SF{SF}, 125 kHz, CR 4/7, {record['bitrate_bps']} bit/s, {record['air_255_ms']} ms per full frame, {PTX} dBm, satellite {os.path.basename(EXE)}")
probe = PassModel(site="user", choose="high", seed=0)
info = probe.describe()
record["pass"] = info
print("pass:", info)
check("the link closes in part of the pass at this setting", info["usable_seconds"] > 0, f"usable {info['usable_seconds']} s of {info['pass_seconds']} s")

print("\n--- 0. clean link at this setting ---")
s1, s2, gs, ue, ok = constellation(None)
check("constellation up", ok)
r = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=True, sat="sat2", sat_id=S2)
check("handshake on the clean link", r["ok"], f"{r['seconds']} s, {r.get('octets_total')} octets")
clean_s = float(r["seconds"])
record["clean"] = dict(seconds=clean_s, octets=r.get("octets_total"), ok=bool(r["ok"]))
close(gs, ue, s1, s2)

done = 0
for i in range(1, RUNS + 1):
    print(f"\n--- {i}. handshake inside the pass, run {i} of {RUNS} ---")
    model = PassModel(site="user", choose="high", seed=100 + i)
    s1, s2, gs, ue, ok = constellation(model)
    check("constellation up", ok)
    off = info["usable_from_s"] if START == "edge" else max(info["usable_from_s"], round(info["pass_seconds"] / 2 - clean_s / 2))
    model.start(off)
    try:
        r = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=True, sat="sat2", sat_id=S2)
    except HandshakeFailed as e:
        r = dict(ok=False, error=str(e), seconds=None)
    endt = model.tau()
    st = dict(model.stats)
    model.stop()
    inside = bool(r["ok"]) and endt <= info["usable_to_s"]
    done += inside
    print(f"   started {off} s after rise, ended {endt:.0f} s after rise; usable window {info['usable_from_s']} to {info['usable_to_s']} s")
    print(f"   user link: {st['sent_removed']} of {st['sent']} sent removed by the model, {st['received_removed']} of {st['received']} received removed")
    print(f"   outcome: {'completed in ' + str(r['seconds']) + ' s' if r['ok'] else 'not completed: ' + str(r.get('error'))}")
    check("handshake completed inside the usable window", inside, f"{r['seconds']} s")
    if r["ok"]:
        check("the three parties derived the same key", bool(r.get("keys_agree", r.get("agree", True))))
    record["runs"].append(dict(run=i, start=START, start_s=off, end_s=round(endt, 1), seconds=r["seconds"], ok=bool(r["ok"]), inside=inside,
                               octets=r.get("octets_total"), uplink=r.get("uplink_segments"), model=st, error=r.get("error")))
    close(gs, ue, s1, s2)

record["completed_inside"] = done
json.dump(record, open(os.path.join(HERE, f"pass_rate_sf{SF}_ptx{int(PTX)}_{START}.json"), "w"), indent=1)
print(f"\n{done} of {RUNS} handshakes completed inside the pass at {record['bitrate_bps']} bit/s")
print(f"{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

#!/usr/bin/env python3
"""Print the measured numbers of the paper from the recorded runs in this folder.

    python3 results/summarize.py

Reads results/hardware/*.json, the bridge logs in results/hardware/logs/ and
results/emulation/*.json.  Needs only the Python standard library.
"""
import glob
import gzip
import json
import os
import re
import statistics as st

HERE = os.path.dirname(os.path.abspath(__file__))
HW = os.path.join(HERE, "hardware")
EMU = os.path.join(HERE, "emulation")


def load(path):
    with open(path) as f:
        return json.load(f)


def title(t):
    print("\n" + t + "\n" + "-" * len(t))


def rng(v, nd=1):
    v = [x for x in v if x is not None]
    if not v:
        return "no completed run"
    if len(v) == 1:
        return f"{v[0]:.{nd}f}"
    return f"mean {st.mean(v):.{nd}f} (min {min(v):.{nd}f}, max {max(v):.{nd}f}, n={len(v)})"


# ---------------------------------------------------------------- handshakes on the hardware
title("Handshakes on the hardware (seconds, octets, uplink segments, downlink frames)")
for path in sorted(glob.glob(os.path.join(HW, "auth_hw_*.json"))):
    name = os.path.basename(path)
    runs = load(path)
    topo = "two satellites, RF ISL" if "_const_" in name else "one satellite"
    orbit = ", modeled pass on the user link" if "_orbit_" in name else ""
    done = [r for r in runs if r.get("ok")]
    print(f"{name}\n   {topo}{orbit}, {len(done)} of {len(runs)} completed")
    for i, r in enumerate(runs, 1):
        if r.get("ok"):
            print(f"   run {i}: {r['seconds']:7.1f} s  {r.get('octets_total')} octets  "
                  f"up {r.get('uplink_segments')} ({r.get('uplink_retransmissions')} retx)  "
                  f"down {r.get('downlink_frames')} ({r.get('downlink_lost')} lost)")
        else:
            print(f"   run {i}: not completed: {r.get('error')}")
        o = r.get("orbit")
        if o:
            print(f"          pass of {o['satellite']}, {o['max_elevation_deg']} deg, {o['pass_seconds']:.0f} s, margin "
                  f"{o['margin_db_at_rise']} dB at rise and {o['margin_db_at_peak']} dB at the peak ({o['profile']}), usable "
                  f"{o['usable_seconds']:.0f} s, started {o['start_offset_s']:.0f} s after rise; the model removed "
                  f"{o['user_link']['sent_removed']} of {o['user_link']['sent']} sent and "
                  f"{o['user_link']['received_removed']} of {o['user_link']['received']} received frames")
    if len(done) > 1:
        print("   all runs:   ", rng([r["seconds"] for r in done]))
        if len(done) > 2:      # a campaign leaves the links under SDLS after its first handshake
            print("   under SDLS: ", rng([r["seconds"] for r in done[1:]]), " (first run of a campaign is on the clear link)")

# ---------------------------------------------------------------- handover
title("Handover on the hardware")
hs, ho, gl = [], [], []
for path in sorted(glob.glob(os.path.join(HW, "handover_hw_*.json"))):
    for r in load(path):
        h, v = r.get("handshake", {}), r.get("handover", {})
        ok = v.get("traffic_delivered") and v.get("derived_key_used")
        print(f"{os.path.basename(path)} run {r.get('run')}: handshake {h.get('seconds')} s, ground link keyed after "
              f"{r.get('ground_link_keyed_after_s')} s, handover {v.get('seconds')} s, protected message delivered under the derived key: {bool(ok)}")
        if ok:
            hs.append(h.get("seconds")); ho.append(v.get("seconds"))
            if r.get("ground_link_keyed_after_s") is not None:
                gl.append(r["ground_link_keyed_after_s"])
if ho:
    print("handover:           ", rng(ho), f" median {st.median(ho):.1f}")
    print("handshake before it:", rng(hs), f" median {st.median(hs):.1f}")
    print(f"ratio of the means:  {st.mean(hs) / st.mean(ho):.1f}")
    print("ground link keyed:  ", rng(gl))

# ---------------------------------------------------------------- satellite computation
title("Satellite cryptography per handshake, from the satellites' own log lines (milliseconds)")
rows = []
for f in ("sat1_bridge_log.csv.gz", "sat1_bridge_log_sat2.csv.gz"):
    p = os.path.join(HW, "logs", f)
    if not os.path.exists(p):
        continue
    with gzip.open(p, "rt", errors="replace") as g:
        for line in g:
            m = re.search(r"satellite crypto this handshake, us: kem (\d+) sign (\d+) verify (\d+) cert (\d+) wrap (\d+)", line)
            if m and line.startswith("2026-11-16"):          # the measurement campaign
                rows.append([int(x) / 1000.0 for x in m.groups()])
if rows:
    ref = [r for r in rows if r[3] == 0]
    full = [r for r in rows if r[3] > 0]
    print(f"{len(rows)} completed handshakes: {len(ref)} by reference, {len(full)} with a full certificate")
    for i, n in enumerate(("ML-KEM-768", "ML-DSA-65 sign", "ML-DSA-65 verify")):
        print(f"   {n:18s}", rng([r[i] for r in rows], 2))
    print(f"   {'AES-256-GCM wrap':18s}", rng([r[4] for r in rows], 2))
    print("   total, reference mode:   ", rng([sum(r) for r in ref], 2))
    for r in full:
        print(f"   total, full certificates: {sum(r):.2f}  (certificate verification {r[3]:.2f})")

# ---------------------------------------------------------------- certificate substitution
title("Certificate substitution on the hardware")
for path in sorted(glob.glob(os.path.join(HW, "cert_substitution_hw_*.json"))):
    d = load(path)
    rule = "with the certificate rule on the board" if "_with_rule_" in path else "board without the certificate rule"
    print(f"{os.path.basename(path)}  ({rule})")
    for a in d.get("attempts", []):
        print(f"   attempt {a['n']}: reached {a['reached']}, stopped: {a.get('error')}; adversary holds the session key: {a['adversary_has_sk']}")
    h = d.get("honest_after", {})
    print("   honest handshake afterward:", f"completed in {h.get('seconds')} s" if h.get("ok") else f"failed ({h.get('error')})")
p = os.path.join(HW, "logs", "sat1_bridge_log.csv.gz")
if os.path.exists(p):
    with gzip.open(p, "rt", errors="replace") as g:
        hits = [l[:19] for l in g if "differs from the installed one" in l]
    print(f"satellite log (with the rule): the satellite logged the rejection of a certificate received in band {len(hits)} times: {', '.join(hits)}")

# ---------------------------------------------------------------- emulation
title("Restart of the inter satellite association on the hardware")
p = os.path.join(HW, "isl_restart_hw_20261117.txt")
if os.path.exists(p):
    print(open(p).read().strip())

title("Emulation: handshake inside one pass at spreading factor 7")
for path in sorted(glob.glob(os.path.join(EMU, "pass_rate_*.json"))):
    d = load(path)
    p = d["pass"]
    print(f"{os.path.basename(path)}: {d['bitrate_bps']} bit/s, model power {d['ptx_dbm']} dBm, usable window {p['usable_seconds']:.0f} s; "
          f"clean link {d['clean']['seconds']} s; in the pass: "
          + ", ".join(f"{r['seconds']} s" if r["ok"] else "failed" for r in d["runs"])
          + f"; {d['completed_inside']} of {len(d['runs'])} inside the window")

title("Emulation: certificate substitution against the flight code")
p = os.path.join(EMU, "cert_substitution.json")
if os.path.exists(p):
    for k, v in load(p).items():
        print(f"variant {k} (certificate rule: {v['policy']}): " + "; ".join(
            f"attempt {a['n']} reached {a['reached']}, adversary holds the key: {a['adversary_has_sk']}" for a in v["attempts"])
            + (f"; honest handshake afterward {v['honest_after']['seconds']} s" if v.get("honest_after") else ""))

title("Emulation: restart of the inter satellite association")
p = os.path.join(EMU, "isl_restart.json")
if os.path.exists(p):
    d = load(p)
    a, b = d["A"], d["B_total"]
    print(f"same key file: {a['replay_accepted']} of {a['recorded']} recorded frames accepted again, "
          f"{a['ivs_reused']} of {a['frames_after']} IVs reused")
    print(f"new key file at each of {d['restarts']} restarts: {b['rejected']} of {b['recorded']} recorded frames rejected, "
          f"{b['pairs_repeated']} of {b['pairs']} key and IV pairs repeated")
print()

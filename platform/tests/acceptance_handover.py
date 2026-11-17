#!/usr/bin/env python3
"""Acceptance test of the merged platform on the bench: the pre arranged handover through
the new dashboard's API, exactly what the GUI's Start button does.

Run on the Linux laptop with the board up (constellation_start.sh), the bridge running on
the Windows laptop with both radios, and the API started from the merged release:

    cd PQSAT
    python3 -m pqsat_testbed.api --db testbed_hw.db --port 8080      (in one terminal)
    python3 platform/tests/acceptance_handover.py                      (in another)

What it checks, in order, and prints as PASS or FAIL:
    1. /api/health answers and the API is mounted with the add on (orbit, registry present)
    2. /api/env reports the bench constellation (two satellites) or pqsat8
    3. /api/nodes lists SAT-1, SAT-2 and USER1 (bootstrap from the manifest if empty)
    4. POST /api/runs {handover_prearranged, hardware, constellation, pqsat, ref} is accepted
    5. /api/state shows the handshake progressing (MSG1 ... MSG8) and then done with keys agreeing
    6. the run finishes with status done and a handover_s in its summary
    7. the handover time is below 60 s (measured 18.7 s on 28 October) and the user link is
       protected on the new satellite
    8. after the run the satellites are back in clear (health advice empty)
Exit code 0 when all pass.
"""
import json
import os
import sys
import time
import urllib.request

API = os.environ.get("PQSAT_API", "http://localhost:8080")
TOKEN = os.environ.get("PQSAT_TOKEN", "")
TIMEOUT_S = 15 * 60


def call(path, body=None):
    req = urllib.request.Request(API + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json", **({"X-Token": TOKEN} if TOKEN else {})},
                                 method="POST" if body is not None else "GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)
    return ok


def main():
    h = call("/api/health")
    check("1 API and add on mounted", h.get("api") and h.get("orbit") and h.get("registry"), json.dumps(h))
    if not h.get("platform_core", True):
        print("the platform core is not loaded (standalone API); merge the release first"); sys.exit(2)
    env = call("/api/env")
    check("2 environment", env["summary"]["satellites"] >= 2, f"{env['constellation']}: {env['summary']['satellites']} satellites")
    nodes = call("/api/nodes")["nodes"]
    if not nodes:
        print("registry empty: bootstrapping from the manifest")
        os.system(f"python3 -m pqsat_testbed.registry --db {os.environ.get('PQSAT_DB', 'testbed_hw.db')} bootstrap --constellation {env['constellation']}")
        nodes = call("/api/nodes")["nodes"]
    names = {n["name"] for n in nodes}
    check("3 nodes registered", {"SAT-1", "SAT-2"} <= names and any(n["kind"] == "user" for n in nodes), ", ".join(sorted(names)))
    body = dict(experiment="handover_prearranged", backend="hardware", topology="constellation", protocol="pqsat", link="clean", mode="ref", params=dict(runs=1))
    r = call("/api/runs", body)
    run_id = r.get("run_id") or r.get("id")
    if not check("4 run accepted", bool(run_id), json.dumps(r)[:200]):
        sys.exit(1)
    t0 = time.time(); seen = set(); done = False; last = None
    while time.time() - t0 < TIMEOUT_S:
        st = call("/api/state")
        hs = st.get("handshake") or {}
        for m in hs.get("msgs", []):
            if m.get("state") == "d" and m["name"] not in seen:
                seen.add(m["name"]); print(f"   {m['name']} {m.get('detail', '')} {m.get('t', '')} s", flush=True)
        runs = call("/api/runs")
        runs = runs if isinstance(runs, list) else runs.get("runs", [])
        me = next((x for x in runs if (x.get("id") or x.get("run_id")) == run_id), None)
        if me and me.get("status") in ("done", "failed", "error"):
            last = me; done = me["status"] == "done"; break
        time.sleep(5)
    check("5 handshake progressed and completed", len(seen) >= 8 and bool((call('/api/state').get('handshake') or {}).get('done')), f"{len(seen)} messages seen")
    check("6 run finished", done, json.dumps(last)[:300] if last else "timeout")
    summ = (last or {}).get("summary") or {}
    if isinstance(summ, str):
        try:
            summ = json.loads(summ)
        except Exception:
            summ = {"text": summ}
    ho = summ.get("handover_s") or summ.get("handover")
    try:
        ho = float(str(ho).split()[0]) if ho is not None else None
    except Exception:
        ho = None
    st = call("/api/state")
    user_link = next((l for l in st.get("links", []) if l["name"].startswith("user")), {})
    check("7 handover time and protected user link", ho is not None and ho < 60 and user_link.get("state") == "protected", f"handover {ho} s, user link {user_link.get('state')}")
    h = call("/api/health")
    check("8 satellites back in clear", not h.get("advice"), json.dumps(h.get("advice")))
    print(f"\n{sum(results)} of {len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()

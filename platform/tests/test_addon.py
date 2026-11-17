"""Self tests of the add on (no flight software needed):
    python3 -m pytest platform/tests/test_addon.py -q      or     python3 platform/tests/test_addon.py
"""
import json, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
# the tests live in platform/tests/ after the merge and in tests/ in the add on itself
for cand in (os.path.join(HERE, ".."), os.path.join(HERE, "..", "platform")):
    if os.path.isdir(os.path.join(cand, "pqsat_testbed")):
        sys.path.insert(0, os.path.abspath(cand)); REL = os.path.abspath(os.path.join(cand, "..")); break
os.environ.setdefault("PQSAT_PQC", os.path.join(REL, "protocol"))


def test_orbit_passes_and_overlap():
    from pqsat_testbed import orbit
    tmp = tempfile.mkdtemp(); orbit.WORK = tmp
    sy = orbit.Synchronizer(orbit.load_manifest("pqsat8"), orbit.load_manifest("ground"), orbit.load_manifest("users"))
    ps = sy.passes(sy.users[0], 0, 24 * 3600)
    assert 40 <= len(ps) <= 70, len(ps)
    overlaps = [max(0, ps[i]["set"] - ps[i + 1]["rise"]) for i in range(len(ps) - 1) if ps[i]["set"]]
    assert max(overlaps) >= 60 and min(overlaps) == 0          # some transitions fit a handover, some do not
    s = sy.slot(ps[5]["rise"] + 100)
    assert any(l.kind == "user" for l in s.links) and any(l.kind == "isl" for l in s.links)


def test_registry_add_revoke():
    from pqsat_testbed import registry, orbit
    tmp = tempfile.mkdtemp(); keys = os.path.join(tmp, "keys"); os.makedirs(keys)
    reg = registry.Registry(os.path.join(tmp, "t.db"), keys, "pqsat8")
    reg.add_ground_station()
    for i in range(3):
        reg.add_satellite()
    u = reg.add_user()
    sats = reg.nodes("satellite")
    assert [s["neighbours"] for s in sats] == [["SAT-3", "SAT-2"], ["SAT-1", "SAT-3"], ["SAT-2", "SAT-1"]]
    assert os.path.exists(os.path.join(keys, "provision", "SAT-1", "satellite.env"))
    reg.revoke("SAT-2", "test")
    assert reg.node("SAT-1")["neighbours"] == ["SAT-3"] and reg.node("SAT-2")["state"] == "revoked"
    assert os.path.exists(os.path.join(keys, "crl.json"))
    m = orbit.load_manifest("pqsat8")
    assert len(m["satellites"]) == 2


def test_standard_analysis_calibration():
    from pqsat_testbed import standard_analysis as A
    sz = A.message_sizes("ML-KEM-768", "ML-DSA-65", False)
    assert abs(sz["total"] - 25312) < 100                        # measured reference mode total
    r = [x for x in A.frame_budget()["rows"] if x["kem"] == "ML-KEM-768" and x["dsa"] == "ML-DSA-65" and x["mode"] == "reference"][0]
    assert 220 < r["seconds"] < 245                              # measured 229.7 s in emulation
    assert "\\begin{table}" in A.extended_procedures()["latex"]


def test_orchestrator_day():
    from pqsat_testbed.api_ext import Env
    from pqsat_testbed.orchestrator import Orchestrator, summarise
    tmp = tempfile.mkdtemp(); os.environ["PQSAT_KEYS"] = os.path.join(tmp, "keys")
    env = Env(os.path.join(tmp, "t.db"), "pqsat8")
    o = Orchestrator(env, nodes=None, log=lambda s: None)
    s = summarise(o.run(12 * 3600, 20, t0=0))
    assert s["handovers"] >= 8 and s["fitting"] >= 1


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)

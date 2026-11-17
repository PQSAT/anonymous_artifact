"""API extension of the platform: environment (orbit layer), nodes (registry), analysis,
attacks catalogue, exports, health and an API token.

Mounted into the platform's FastAPI application by two lines in api.py:

    from pqsat_testbed.api_ext import mount
    mount(app, db_path=a.db)

and runnable on its own (python3 -m pqsat_testbed.api_ext --db testbed.db --port 8080),
in which case it serves the dashboard with the orbit layer live and the experiment
endpoints answering "platform core not loaded" so the GUI can be used and tested without
the flight software present.

Endpoints
    GET  /api/env                      the environment: constellation summary, manifests, slot clock
    POST /api/env                      {"constellation":"pqsat8"} select a manifest (or upload one as {"manifest":{...}})
    GET  /api/env/slot?t=              slot state at emulated time t (positions, links, serving, feeder)
    GET  /api/env/schedule?t0=&duration=&step=   slot by slot
    GET  /api/env/passes?site=&t0=&hours=        pass schedule at a site
    GET  /api/env/handover_plan?user=&t0=&hours=
    POST /api/env/clock                {"t":..., "speed":...} set the emulated clock the orchestrator follows
    GET  /api/nodes                    all nodes with lifecycle state
    POST /api/nodes/satellite          add a satellite (name, scid, plane, slot, uplink_mhz, downlink_mhz, runs_on, neighbours)
    POST /api/nodes/user               add a user (name, id, lat, lon, radio, policy)
    POST /api/nodes/{name}/provision   rewrite its provisioning files; returns the file list
    POST /api/nodes/{name}/rotate      new certificate and keys
    POST /api/nodes/{name}/revoke      {"reason": ...}; returns the CRL
    POST /api/nodes/{name}/state       {"state": "deployed"} operator confirmation
    GET  /api/nodes/{name}/bundle      download the provisioning bundle (tgz)
    GET  /api/nodes/events
    GET  /api/crl
    GET  /api/analysis/frame_budget|replay_window|extended_procedures|findings   rows and LaTeX
    GET  /api/attacks/catalogue
    GET  /api/export/{table}.csv  and  /api/export/paper_tables.tex
    GET  /api/health                   bridge, radios, satellites in clear, database, API
    GET  /                             the dashboard
Every endpoint except / and /api/health requires the header X-Token when PQSAT_TOKEN is set.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import time
from typing import Optional

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response

from . import attacks12, orbit, registry as reg_mod, standard_analysis as SA

HERE = os.path.dirname(os.path.abspath(__file__))
GUI = os.path.join(HERE, "gui", "index.html")


class Env:
    """The live environment: the selected constellation, its synchronizer and the emulated clock."""

    def __init__(self, db_path: str, constellation: str = "pqsat8"):
        self.db_path = db_path
        self.registry = reg_mod.Registry(db_path, constellation=constellation)
        self.select(constellation)
        self.t0_wall = time.time()
        self.t_offset = 0.0
        self.speed = 1.0
        self.hil = {}                       # board -> satellite name

    def select(self, constellation: str, manifest: Optional[dict] = None):
        if manifest:
            orbit.save_manifest(manifest, constellation)
        self.constellation = constellation
        self.registry.constellation = constellation
        self.sync = orbit.Synchronizer(orbit.load_manifest(constellation), orbit.load_manifest("ground"), orbit.load_manifest("users"))

    def reload(self):
        self.select(self.constellation)

    def now(self) -> float:
        return self.t_offset + (time.time() - self.t0_wall) * self.speed

    def set_clock(self, t: Optional[float] = None, speed: Optional[float] = None):
        cur = self.now()
        self.t0_wall = time.time()
        self.t_offset = cur if t is None else float(t)
        if speed is not None:
            self.speed = float(speed)

    def slot(self, t: Optional[float] = None) -> dict:
        t = self.now() if t is None else t
        s = self.sync.slot(t)
        m = self.sync.m
        static = bool(m.get("static"))
        # hardware in the loop: which boards play which satellites this slot
        hil = {}
        policy = m.get("hardware_in_the_loop", {})
        serving = next(iter(s.serving.values()), None) if s.serving else None
        feeder = next(iter(s.feeder.values()), None) if s.feeder else None
        for board, role in policy.items():
            if role == "serving" and serving:
                hil[board] = serving
            elif role == "next":
                nxt = self._next_satellite(t)
                if nxt:
                    hil[board] = nxt
            elif role == "feeder" and feeder:
                hil[board] = feeder
            elif role not in ("serving", "next", "feeder"):
                hil[board] = role
        for sat in self.sync.sats:                # boards fixed in the manifest (the bench)
            if str(sat.get("runs_on", "")).lower().startswith("versal"):
                hil.setdefault(sat["runs_on"], sat["name"])
        self.hil = hil
        return dict(t=t, static=static, positions=s.positions, serving=s.serving, feeder=s.feeder, next=self._next_satellite(t),
                    links=[l.__dict__ for l in s.links], elevations=s.elevations, hil=hil,
                    events=self.sync.events[-20:])

    def _next_satellite(self, t: float) -> Optional[str]:
        if not self.sync.users:
            return None
        u = self.sync.users[0]
        ps = self.sync.passes(u, t, 3 * 3600)
        cur = self.sync._serving.get(u["name"])
        for p in ps:
            if p["satellite"] != cur and p["rise"] > t - 1:
                return p["satellite"]
        return None


def mount(app: FastAPI, db_path: str, constellation: str = "pqsat8", platform=None) -> Env:
    env = Env(db_path, constellation)
    token = os.environ.get("PQSAT_TOKEN")
    r = APIRouter()

    def check(req: Request):
        if token and req.headers.get("x-token") != token and req.query_params.get("token") != token:
            raise HTTPException(401, "token required (X-Token header)")

    # ---------------------------------------------------------------- environment
    @r.get("/api/env")
    def get_env(req: Request):
        check(req)
        m = env.sync.m
        return dict(constellation=env.constellation, summary=env.sync.summary(), manifest=m, ground=env.sync.ground, users=env.sync.users,
                    clock=dict(t=env.now(), speed=env.speed), hil=env.hil, available=_manifests())

    @r.post("/api/env")
    async def post_env(req: Request):
        check(req)
        body = await req.json()
        env.select(body.get("constellation", env.constellation), body.get("manifest"))
        if body.get("clock"):
            env.set_clock(body["clock"].get("t"), body["clock"].get("speed"))
        return get_env(req)

    @r.post("/api/env/clock")
    async def clock(req: Request):
        check(req)
        body = await req.json()
        env.set_clock(body.get("t"), body.get("speed"))
        return dict(t=env.now(), speed=env.speed)

    @r.get("/api/env/slot")
    def slot(req: Request, t: Optional[float] = None):
        check(req)
        return env.slot(t)

    @r.get("/api/env/schedule")
    def schedule(req: Request, t0: float = 0, duration: float = 3600, step: float = 10):
        check(req)
        if duration / step > 20000:
            raise HTTPException(400, "too many slots; raise step")
        return env.sync.schedule(t0, duration, step)

    @r.get("/api/env/passes")
    def passes(req: Request, site: Optional[str] = None, t0: Optional[float] = None, hours: float = 3):
        check(req)
        t0 = env.now() if t0 is None else t0
        sites = env.sync.ground + env.sync.users
        s = next((x for x in sites if x["name"] == site), sites[0] if sites else None)
        if s is None:
            return []
        return env.sync.passes(s, t0, hours * 3600)

    @r.get("/api/env/handover_plan")
    def hplan(req: Request, user: Optional[str] = None, t0: Optional[float] = None, hours: float = 3):
        check(req)
        t0 = env.now() if t0 is None else t0
        u = next((x for x in env.sync.users if x["name"] == user), env.sync.users[0] if env.sync.users else None)
        if u is None:
            return []
        return orbit.handover_plan(env.sync, u, t0, hours * 3600)

    # ---------------------------------------------------------------- nodes
    @r.get("/api/nodes")
    def nodes(req: Request):
        check(req)
        return dict(nodes=env.registry.nodes(), crl=env.registry.crl(), isl_keys=[dict(x) for x in env.registry.db.execute("SELECT a,b,created,retired FROM isl_keys").fetchall()])

    @r.post("/api/nodes/satellite")
    async def add_sat(req: Request):
        check(req)
        b = await req.json()
        try:
            n = env.registry.add_satellite(b.get("name") or None, int(b["scid"], 0) if isinstance(b.get("scid"), str) and b.get("scid") else (b.get("scid") or None),
                                           int(b.get("plane", 0)), b.get("slot"), b.get("uplink_mhz"), b.get("downlink_mhz"), b.get("runs_on", "emulator"),
                                           b.get("neighbours") or None, int(b.get("validity_days", 365)), b.get("notes", ""))
        except reg_mod.RegistryError as e:
            raise HTTPException(400, str(e))
        env.reload()
        return n

    @r.post("/api/nodes/user")
    async def add_user(req: Request):
        check(req)
        b = await req.json()
        try:
            n = env.registry.add_user(b.get("name") or None, int(b["id"], 0) if isinstance(b.get("id"), str) and b.get("id") else (b.get("id") or None),
                                      float(b.get("lat", 54.584)), float(b.get("lon", -5.933)), float(b.get("alt_km", 0.02)), b.get("radio", "/dev/ttyACM1"),
                                      b.get("policy", "longest_remaining"), int(b.get("validity_days", 365)), b.get("notes", ""))
        except reg_mod.RegistryError as e:
            raise HTTPException(400, str(e))
        env.reload()
        return n

    @r.post("/api/nodes/{name}/provision")
    def provision(name: str, req: Request):
        check(req)
        try:
            return env.registry.provision(name)
        except reg_mod.RegistryError as e:
            raise HTTPException(400, str(e))

    @r.post("/api/nodes/{name}/rotate")
    def rotate(name: str, req: Request):
        check(req)
        try:
            return env.registry.rotate(name)
        except reg_mod.RegistryError as e:
            raise HTTPException(400, str(e))

    @r.post("/api/nodes/{name}/revoke")
    async def revoke(name: str, req: Request):
        check(req)
        b = await req.json() if req.headers.get("content-length") not in (None, "0") else {}
        try:
            crl = env.registry.revoke(name, b.get("reason", "operator"))
        except reg_mod.RegistryError as e:
            raise HTTPException(400, str(e))
        env.reload()
        return crl

    @r.post("/api/nodes/{name}/state")
    async def set_state(name: str, req: Request):
        check(req)
        b = await req.json()
        try:
            env.registry.mark(name, b["state"], b.get("detail", "operator"))
        except reg_mod.RegistryError as e:
            raise HTTPException(400, str(e))
        return env.registry.node(name)

    @r.get("/api/nodes/{name}/bundle")
    def bundle(name: str, req: Request):
        check(req)
        n = env.registry.node(name)
        if not n:
            raise HTTPException(404, "unknown node")
        d = os.path.join(env.registry.keys, "provision", name)
        tgz = [f for f in os.listdir(d) if f.endswith(".tgz")] if os.path.isdir(d) else []
        if tgz:
            return FileResponse(os.path.join(d, tgz[0]), filename=tgz[0])
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            tf.add(d, arcname=name)
        return Response(buf.getvalue(), media_type="application/gzip", headers={"Content-Disposition": f"attachment; filename={name}_provision.tgz"})

    @r.get("/api/nodes/events")
    def node_events(req: Request, name: Optional[str] = None, limit: int = 100):
        check(req)
        return env.registry.events(name, limit)

    @r.get("/api/crl")
    def crl(req: Request):
        check(req)
        p = os.path.join(env.registry.keys, "crl.json")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        return dict(body=json.dumps(env.registry.crl()), sig="", digest="")

    # ---------------------------------------------------------------- analysis, attacks, exports
    @r.get("/api/analysis/{which}")
    def analysis(which: str, req: Request):
        check(req)
        if which == "frame_budget":
            return SA.frame_budget()
        if which == "replay_window":
            return SA.replay_window()
        if which == "extended_procedures":
            return SA.extended_procedures()
        if which == "findings":
            return dict(rows=SA.findings(_measured(db_path)))
        raise HTTPException(404, "unknown analysis")

    @r.get("/api/attacks/catalogue")
    def attacks(req: Request):
        check(req)
        rows = attacks12.catalogue()
        try:
            db = sqlite3.connect(db_path)
            for row in rows:
                last = db.execute("SELECT outcome, rejected_by, capture FROM attacks WHERE cls=? AND variant='protected' ORDER BY t DESC LIMIT 1", (row["key"],)).fetchone()
                base = db.execute("SELECT outcome FROM attacks WHERE cls=? AND variant='baseline' ORDER BY t DESC LIMIT 1", (row["key"],)).fetchone()
                row["last"] = dict(outcome=last[0], rejected_by=last[1], capture=last[2]) if last else None
                row["last_baseline"] = base[0] if base else None
            db.close()
        except Exception:
            pass
        return rows

    @r.get("/api/export/{name}")
    def export(name: str, req: Request):
        check(req)
        if name == "paper_tables.tex":
            tex = "\n".join([SA.frame_budget()["latex"], SA.replay_window()["latex"], SA.extended_procedures()["latex"], _findings_tex(db_path)])
            return PlainTextResponse(tex, media_type="text/x-tex")
        if name.endswith(".csv"):
            table = name[:-4]
            if not table.replace("_", "").isalnum():
                raise HTTPException(400, "bad table")
            db = sqlite3.connect(db_path)
            try:
                cur = db.execute(f"SELECT * FROM {table}")
            except sqlite3.Error as e:
                raise HTTPException(404, str(e))
            out = io.StringIO(); w = csv.writer(out)
            w.writerow([d[0] for d in cur.description]); w.writerows(cur.fetchall()); db.close()
            return PlainTextResponse(out.getvalue(), media_type="text/csv")
        raise HTTPException(404, "unknown export")

    @r.get("/api/health")
    def health():
        h = dict(api=True, database=os.path.exists(db_path), orbit=True, registry=True)
        h["platform_core"] = platform is not None
        h["bridge"] = _probe_bridge()
        h["radios"] = [p for p in ("/dev/ttyACM0", "/dev/ttyACM1") if os.path.exists(p)]
        h["advice"] = [] if h["bridge"] or platform is None else ["bridge not reachable: start sat_bridge.py on the Windows laptop, then restart sat1 and sat2 services if the satellites are keyed"]
        return h

    @r.get("/", response_class=HTMLResponse)
    def index():
        with open(GUI, encoding="utf-8") as f:
            return f.read()

    app.include_router(r)
    app.state.env = env
    return env


def _manifests():
    out = []
    for d in (orbit.WORK, orbit.MANIFESTS):
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(".json") and f not in ("ground.json", "users.json") and f[:-5] not in out:
                    out.append(f[:-5])
    return out


def _measured(db_path: str) -> dict:
    """Numbers for the findings table from the platform database when it has them."""
    m = {}
    try:
        db = sqlite3.connect(db_path)
        r = db.execute("SELECT AVG(seconds) FROM handshakes WHERE mode='full' AND ok=1").fetchone()
        if r and r[0]:
            m["full_mode_s"] = round(r[0], 1)
        r = db.execute("SELECT AVG(seconds) FROM handshakes WHERE mode='ref' AND ok=1").fetchone()
        if r and r[0]:
            m["ref_mode_s"] = round(r[0], 1)
        db.close()
    except Exception:
        pass
    return m


def _findings_tex(db_path: str) -> str:
    rows = SA.findings(_measured(db_path))
    return SA._latex(rows, ["limitation", "measurement", "fix"], "Limitations of the deployed standard found on the testbed, with the measurement and the fix", "tab:findings")


def _probe_bridge() -> bool:
    import socket
    host, port = os.environ.get("PQSAT_BRIDGE", "localhost:7331").split(":")
    try:
        with socket.create_connection((host, int(port)), timeout=0.3):
            return True
    except OSError:
        return False


def standalone(db: str, port: int, host: str = "0.0.0.0", constellation: str = "pqsat8"):
    app = FastAPI(title="PQSAT constellation testbed (orbit layer, registry, analysis)")
    env = mount(app, db, constellation, platform=None)

    @app.get("/api/catalogue")
    def catalogue():
        return dict(version="0.4", db=os.path.basename(db), experiments=[dict(name=n, description=d) for n, d in [
            ("handover_geometry", "handover fired by pass end (orbit layer)"), ("handshake", "three party handshake"), ("traffic", "latency, RTT, throughput"),
            ("handover", "new handshake with the target"), ("handover_prearranged", "session key over the ISL"), ("attacks", "twelve classes, adversary radio"),
            ("satellite_failure", "one satellite lost"), ("predict", "completion time model")]],
            backends=["emulator + hardware in the loop", "emulator", "hardware"], topologies=["pqsat8", "bench", "constellation", "chain", "single"],
            protocols=[dict(name="pqsat", description="ML-KEM-768 + ML-DSA-65 three party"), dict(name="classical", description="ECDH P-256 and ECDSA P-256")],
            links=[dict(name="orbit", description="delay and loss from geometry, adaptive SF"), dict(name="clean", description="no frame loss, half duplex"),
                   dict(name="loss10", description="10 percent frame loss"), dict(name="loss20", description="20 percent frame loss")],
            core_loaded=False)

    @app.get("/api/state")
    def state():
        s = env.slot()
        return dict(core_loaded=False, slot=s, serving=next(iter(s["serving"].values()), None), feeder=next(iter(s["feeder"].values()), None), hil=s["hil"], nodes={})

    @app.get("/api/runs")
    def runs():
        try:
            dbc = sqlite3.connect(db)
            rows = [dict(zip([c[0] for c in cur.description], r)) for cur in [dbc.execute("SELECT * FROM runs ORDER BY rowid DESC LIMIT 50")] for r in cur.fetchall()]
            dbc.close(); return rows
        except Exception:
            return []

    @app.post("/api/runs")
    async def post_run(req: Request):
        return dict(error="platform core not loaded in standalone mode; integrate with the release to run experiments", body=await req.json())

    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="testbed.db"); ap.add_argument("--port", type=int, default=8080); ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--constellation", default="pqsat8")
    a = ap.parse_args()
    standalone(a.db, a.port, a.host, a.constellation)

"""REST and websocket API of the testbed.  The GUI is a client of this and nothing else.

    python3 -m pqsat_testbed.api --db testbed.db --port 8080

    GET  /                      the GUI
    GET  /api/catalogue         protocols, link models, experiments, attacks available
    GET  /api/state             live state of the running experiment (nodes, links, SDLS)
    POST /api/runs              start an experiment: {"experiment": "handshake", "backend": "emulator",
                                "topology": "constellation", "protocol": "pqsat", "link": "clean",
                                "mode": "ref", "params": {"runs": 3}}  -> {"run_id": ...}
    GET  /api/runs              recorded runs, newest first
    GET  /api/runs/{id}         one run: configuration, status, summary
    GET  /api/runs/{id}/handshakes   handshake records of the run (messages, metrics, logs)
    GET  /api/runs/{id}/events       satellite log lines of the run
    GET  /api/runs/{id}/samples      metric samples (link RTT, application RTT, latency, handover)
    POST /api/runs/{id}/replay       rerun the configuration on the emulator
    GET  /api/dataset/{table}.csv    export a table: runs, handshakes, messages, frames, samples, events
    WS   /api/live                   every live event of every run as JSON

One experiment runs at a time (one channel, one board); requests queue.
"""
import argparse
import asyncio
import json
import os
import queue
import threading

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pqsat_testbed.api_ext import mount as _mount_ext  # add on: orbit layer, registry, analysis
from pqsat_testbed.state_adapter import extend_state as _extend_state, translate_event as _translate_event  # add on
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse

from pqsat_testbed import Platform, __version__
from pqsat_testbed.plugins import catalogue

HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="pqsat testbed", version=__version__)
PLATFORM = None
EVENTS = []                 # last events kept for late subscribers
SUBS = set()                # asyncio queues of websocket clients
LOOP = None
JOBQ = queue.Queue()
PENDING = {}


def _on_event(ev):
    EVENTS.append(ev)
    del EVENTS[:-2000]
    if LOOP is not None:
        for q in list(SUBS):
            LOOP.call_soon_threadsafe(q.put_nowait, ev)


def _worker():
    while True:
        job = JOBQ.get()
        PENDING.pop(job["run_id"], None)
        PLATFORM.run(job["experiment"], backend=job["backend"], topology=job["topology"], protocol=job["protocol"],
                     link=job["link"], mode=job["mode"], note=job.get("note", ""), run_id=job["run_id"],
                     **job.get("params", {}))


@app.on_event("startup")
async def _startup():
    global LOOP
    LOOP = asyncio.get_event_loop()


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(HERE, "gui", "index.html"), encoding="utf-8") as f:
        return f.read()


@app.get("/api/catalogue")
def api_catalogue():
    return catalogue()


@app.get("/api/state")
def api_state():
    st = PLATFORM.state()
    st["queued"] = list(PENDING.keys())
    return st


@app.post("/api/runs")
def api_start(body: dict):
    import time
    import uuid
    exp = body.get("experiment", "handshake")
    run_id = time.strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
    job = dict(run_id=run_id, experiment=exp, backend=body.get("backend", "emulator"),
               topology=body.get("topology", "single"), protocol=body.get("protocol", "pqsat"),
               link=body.get("link", "clean"), mode=body.get("mode", "ref"), note=body.get("note", ""),
               params=body.get("params", {}))
    cat = catalogue()
    for key, reg in (("experiment", "experiments"), ("protocol", "protocols"), ("link", "links")):
        if job[key] not in cat[reg]:
            raise HTTPException(400, f"unknown {key} {job[key]}")
    PENDING[run_id] = job
    JOBQ.put(job)
    return dict(run_id=run_id, queued=JOBQ.qsize())


@app.get("/api/runs")
def api_runs(limit: int = 100):
    return PLATFORM.db.runs(limit)


@app.get("/api/runs/{run_id}")
def api_run(run_id: str):
    r = PLATFORM.db.run(run_id)
    if r is None:
        if run_id in PENDING:
            return dict(id=run_id, status="queued", config=PENDING[run_id])
        raise HTTPException(404, "no such run")
    return r


@app.get("/api/runs/{run_id}/handshakes")
def api_handshakes(run_id: str):
    return PLATFORM.db.handshakes(run_id)


@app.get("/api/runs/{run_id}/events")
def api_events(run_id: str):
    return PLATFORM.db.events(run_id)


@app.get("/api/runs/{run_id}/samples")
def api_samples(run_id: str, kind: str = None):
    return PLATFORM.db.samples(run_id, kind)


@app.post("/api/runs/{run_id}/replay")
def api_replay(run_id: str):
    r = PLATFORM.db.run(run_id)
    if r is None:
        raise HTTPException(404, "no such run")
    c = r["config"]
    return api_start(dict(experiment=c["experiment"], backend="emulator", topology=c["topology"],
                          protocol=c["protocol"], link=c["link"], mode=c["mode"], params=c.get("params", {}),
                          note=f"replay of {run_id}"))


@app.get("/api/dataset/{table}.csv")
def api_dataset(table: str):
    if table not in ("runs", "handshakes", "messages", "frames", "samples", "events"):
        raise HTTPException(404, "no such table")
    path = os.path.join("/tmp", f"pqsat_{table}.csv")
    PLATFORM.db.export_csv(table, path)
    return FileResponse(path, media_type="text/csv", filename=f"{table}.csv")


@app.get("/api/protocol.md", response_class=PlainTextResponse)
def api_protocol():
    from pqsat_testbed import paths
    p = os.path.join(paths.PQC, "PROTOCOL.md")
    return open(p, encoding="utf-8").read() if os.path.exists(p) else "protocol document not found"


@app.websocket("/api/live")
async def api_live(ws: WebSocket):
    await ws.accept()
    q = asyncio.Queue()
    SUBS.add(q)
    try:
        for ev in EVENTS[-50:]:
            await ws.send_text(json.dumps(ev, default=str))
        while True:
            ev = await q.get()
            await ws.send_text(json.dumps(ev, default=str))
    except WebSocketDisconnect:
        pass
    finally:
        SUBS.discard(q)


def main():
    global PLATFORM
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="testbed.db")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--import-dir", help="import past campaign JSON files from this directory at start")
    a = ap.parse_args()
    _mount_ext(app, db_path=a.db, platform=globals().get('platform') or globals().get('PLATFORM'))  # add on
    PLATFORM = Platform(db=a.db)
    PLATFORM.subscribe(_on_event)
    if a.import_dir:
        print("imported", PLATFORM.import_dir(a.import_dir))
    threading.Thread(target=_worker, daemon=True).start()
    import uvicorn
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()

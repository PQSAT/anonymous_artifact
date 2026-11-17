"""Emulator API, first form.

Runs the three party post quantum handshake over the emulated CCSDS link (the real
flight satellite core as a process, the real user and ground station libraries, a
simulated LoRa channel) on request, and returns the measured record.  One handshake at a
time; jobs are queued.

    python3 emulator_api.py --port 8080

    POST /handshake   {"mode": "full"|"ref", "loss": 0.0..0.5, "preload": true}
                      -> {"job": id}
    GET  /job/<id>    -> {"state": "queued"|"running"|"done"|"failed", "result": {...}}
    GET  /jobs        -> list
    GET  /protocol    -> the protocol specification (PROTOCOL.md)
    GET  /            -> this text

The result record is the one handshake_runner.run_handshake produces: per message octets,
uplink segments, COP-1 retransmissions, downlink frames, frames lost, NAK rounds, chunks
repaired, seconds; totals; the session keys as held by user and ground (so a caller can
see that they agree); the primitive timings on user and ground.  The satellite log lines
for the run are attached.

The same run_handshake drives the radio link; a later version of this service selects
between the emulated channel and the hardware in the laboratory.
"""
import argparse
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, ".."))
TEST = os.environ.get("SAT_TEST_DIR", os.path.join(REL, "flight", "apps", "sat_rf", "test"))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, TEST)
sys.path.insert(0, HERE)
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1  # noqa: E402
from sim_link import SimSatellite, SimModem                                        # noqa: E402
from handshake_runner import run_handshake                                         # noqa: E402
from pqsat_roles import HandshakeFailed                                            # noqa: E402

JOBS = {}
QUEUE = []
LOCK = threading.Lock()


def run_job(job):
    mode, loss, preload = job["mode"], job["loss"], job["preload"]
    env = dict(SAT_AUTH_DIR=os.path.join(HERE, "keys"))
    if mode == "ref":
        env["SAT_AUTH_REF"] = "1"
        env["SAT_AUTH_PRELOAD_UE"] = "1"
    for k in ("SAT_AUTH_REF", "SAT_AUTH_PRELOAD_UE"):
        os.environ.pop(k, None)
    os.environ.update(env)
    sat = SimSatellite(os.path.join(TEST, "satsim"), loss=loss, debug=False)
    gs = Terminal(SimModem(sat, "GS", loss=loss), ADDR_GS, TC_VC_GROUND, name="GS", show_hk=False).start()
    ue = Terminal(SimModem(sat, "USER1", loss=loss), ADDR_USER1, TC_VC_USER1, name="USER1", show_hk=False,
                  show_relay=False).start()
    try:
        end = time.time() + 30
        while gs.hk is None and time.time() < end:
            time.sleep(0.2)
        if gs.hk is None or not gs.init_cop() or not ue.init_cop() or gs.set_time() != "OK":
            raise HandshakeFailed("link did not come up")
        r = run_handshake(ue, gs, mode=mode, preload=preload, verbose=False)
    except HandshakeFailed as e:
        r = dict(mode=mode, ok=False, error=str(e))
    finally:
        r["satellite_log"] = list(sat.log)
        r["link_stats"] = dict(user=ue.stats, ground=gs.stats)
        gs._run = ue._run = False
        sat.close()
    return r


def worker():
    while True:
        with LOCK:
            job = QUEUE.pop(0) if QUEUE else None
        if job is None:
            time.sleep(0.5)
            continue
        job["state"] = "running"
        job["started"] = time.time()
        try:
            job["result"] = run_job(job)
            job["state"] = "done" if job["result"].get("ok") else "failed"
        except Exception as e:  # noqa: BLE001
            job["result"] = dict(ok=False, error=repr(e))
            job["state"] = "failed"
        job["finished"] = time.time()


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            return self._send(200, __doc__, "text/plain")
        if self.path == "/protocol":
            with open(os.path.join(HERE, "PROTOCOL.md")) as f:
                return self._send(200, f.read(), "text/markdown")
        if self.path == "/jobs":
            return self._send(200, [{k: v for k, v in j.items() if k != "result"} for j in JOBS.values()])
        if self.path.startswith("/job/"):
            j = JOBS.get(self.path[5:])
            return self._send(200, j) if j else self._send(404, {"error": "no such job"})
        self._send(404, {"error": "unknown path"})

    def do_POST(self):
        if self.path != "/handshake":
            return self._send(404, {"error": "unknown path"})
        n = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
            mode = req.get("mode", "full")
            loss = float(req.get("loss", 0.0))
            preload = bool(req.get("preload", True))
            if mode not in ("full", "ref") or not 0.0 <= loss <= 0.5:
                raise ValueError("mode must be full or ref, loss 0.0 to 0.5")
        except (ValueError, json.JSONDecodeError) as e:
            return self._send(400, {"error": str(e)})
        job = dict(job=uuid.uuid4().hex[:12], mode=mode, loss=loss, preload=preload, state="queued",
                   submitted=time.time())
        with LOCK:
            JOBS[job["job"]] = job
            QUEUE.append(job)
        self._send(202, {"job": job["job"], "queued_ahead": len(QUEUE) - 1})

    def log_message(self, fmt, *args):
        sys.stderr.write("api: " + fmt % args + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="127.0.0.1")
    a = ap.parse_args()
    threading.Thread(target=worker, daemon=True).start()
    srv = ThreadingHTTPServer((a.bind, a.port), H)
    print(f"emulator API on http://{a.bind}:{a.port}/  (POST /handshake, GET /job/<id>)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

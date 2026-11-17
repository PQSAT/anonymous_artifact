"""Record database: every run of the testbed, in emulation or on the hardware, in one
SQLite file with the same schema, so emulation and hardware are directly comparable and
a dataset can be exported for anyone who only wants the numbers.

Tables
    runs        one row per experiment run (configuration, backend, topology, status, summary)
    handshakes  one row per handshake inside a run (totals, metrics, session key agreement)
    messages    one row per protocol message inside a handshake (octets, segments, frames, seconds)
    frames      one row per frame seen by a terminal (time, node, direction, octets, vc, rssi, snr, air time)
    samples     metric samples: link RTT per segment, application RTT, one way latency, per node
    events      satellite log lines with time and node

Past campaigns (the JSON files of auth_campaign.py and the emulation tests) import with
Database.import_campaign so the dataset starts with every measurement made so far.
"""
import csv
import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, started REAL, finished REAL, backend TEXT, topology TEXT, protocol TEXT,
    experiment TEXT, mode TEXT, config TEXT, status TEXT, summary TEXT, platform_version TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS handshakes (
    run_id TEXT, n INTEGER, started TEXT, ok INTEGER, seconds REAL, octets INTEGER, up_segments INTEGER,
    up_retx INTEGER, down_frames INTEGER, down_lost INTEGER, naks INTEGER, repaired INTEGER,
    serving_satellite TEXT, sk_agree INTEGER, goodput_Bps REAL, metrics TEXT, record TEXT,
    PRIMARY KEY (run_id, n));
CREATE TABLE IF NOT EXISTS messages (
    run_id TEXT, handshake INTEGER, idx INTEGER, name TEXT, direction TEXT, octets INTEGER, segments INTEGER,
    retx INTEGER, frames INTEGER, lost INTEGER, naks INTEGER, repaired INTEGER, seconds REAL);
CREATE TABLE IF NOT EXISTS frames (
    run_id TEXT, t REAL, node TEXT, dir TEXT, bytes INTEGER, vc INTEGER, rssi REAL, snr REAL, air_ms REAL);
CREATE TABLE IF NOT EXISTS samples (
    run_id TEXT, t REAL, node TEXT, kind TEXT, value REAL, extra TEXT);
CREATE TABLE IF NOT EXISTS events (
    run_id TEXT, t REAL, node TEXT, text TEXT);
CREATE INDEX IF NOT EXISTS frames_run ON frames (run_id);
CREATE INDEX IF NOT EXISTS samples_run ON samples (run_id);
CREATE INDEX IF NOT EXISTS events_run ON events (run_id);
"""


class Database:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.c = sqlite3.connect(path, check_same_thread=False)
        self.c.executescript(SCHEMA)

    # ---------------- runs ----------------
    def start_run(self, run_id, backend, topology, protocol, experiment, mode, config, version, note=""):
        self.c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id, time.time(), None, backend, topology, protocol, experiment, mode,
                        json.dumps(config), "running", None, version, note))
        self.c.commit()

    def finish_run(self, run_id, status, summary):
        self.c.execute("UPDATE runs SET finished=?, status=?, summary=? WHERE id=?",
                       (time.time(), status, json.dumps(summary), run_id))
        self.c.commit()

    def run(self, run_id):
        r = self.c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._row(r, "runs") if r else None

    def runs(self, limit=200):
        rows = self.c.execute("SELECT * FROM runs ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(r, "runs") for r in rows]

    def _row(self, r, table):
        cols = [d[1] for d in self.c.execute(f"PRAGMA table_info({table})")]
        d = dict(zip(cols, r))
        for k in ("config", "summary", "metrics", "record", "extra"):
            if k in d and isinstance(d[k], str):
                try:
                    d[k] = json.loads(d[k])
                except ValueError:
                    pass
        return d

    # ---------------- handshakes and messages ----------------
    def add_handshake(self, run_id, n, rec, metrics=None):
        octets = rec.get("octets_total", 0)
        sec = rec.get("seconds") or 0
        self.c.execute("INSERT OR REPLACE INTO handshakes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (run_id, n, rec.get("started", ""), int(bool(rec.get("ok"))), sec, octets,
                        rec.get("uplink_segments", 0), rec.get("uplink_retransmissions", 0),
                        rec.get("downlink_frames", 0), rec.get("downlink_lost", 0), rec.get("downlink_naks", 0),
                        rec.get("downlink_repaired", 0), rec.get("serving_satellite", ""),
                        int(bool(rec.get("ok") and rec.get("sk_user") == rec.get("sk_ground"))),
                        round(octets / sec, 2) if sec else None, json.dumps(metrics or {}), json.dumps(rec)))
        for i, m in enumerate(rec.get("messages", [])):
            self.c.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (run_id, n, i, m.get("msg"), m.get("direction"), m.get("octets"), m.get("segments"),
                            m.get("retransmissions"), m.get("frames"), m.get("lost"), m.get("naks"),
                            m.get("repaired"), m.get("seconds")))
        self.c.commit()

    def handshakes(self, run_id=None):
        q = "SELECT * FROM handshakes" + (" WHERE run_id=?" if run_id else "") + " ORDER BY run_id, n"
        rows = self.c.execute(q, (run_id,) if run_id else ()).fetchall()
        return [self._row(r, "handshakes") for r in rows]

    # ---------------- frames, samples, events ----------------
    def add_terminal_samples(self, run_id, node, samples):
        fr, sm = [], []
        for x in samples:
            if x["kind"] in ("tx", "rx"):
                fr.append((run_id, x["t"], node, "up" if x["kind"] == "tx" else "down", x["bytes"],
                           x.get("vc"), x.get("rssi"), x.get("snr"), x.get("air_ms")))
            else:
                v = x.get("ms", x.get("value"))
                extra = {k: v2 for k, v2 in x.items() if k not in ("t", "kind", "ms", "value")}
                sm.append((run_id, x["t"], node, x["kind"], v, json.dumps(extra)))
        self.c.executemany("INSERT INTO frames VALUES (?,?,?,?,?,?,?,?,?)", fr)
        self.c.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?)", sm)
        self.c.commit()

    def add_sample(self, run_id, node, kind, value, t=None, **extra):
        self.c.execute("INSERT INTO samples VALUES (?,?,?,?,?,?)",
                       (run_id, t or time.time(), node, kind, value, json.dumps(extra)))
        self.c.commit()

    def add_events(self, run_id, node, lines, times=None):
        rows = [(run_id, (times[i] if times and i < len(times) else None), node, l) for i, l in enumerate(lines)]
        self.c.executemany("INSERT INTO events VALUES (?,?,?,?)", rows)
        self.c.commit()

    def events(self, run_id):
        return [dict(t=t, node=n, text=x) for t, n, x in
                self.c.execute("SELECT t,node,text FROM events WHERE run_id=? ORDER BY rowid", (run_id,))]

    def samples(self, run_id, kind=None):
        q = "SELECT t,node,kind,value,extra FROM samples WHERE run_id=?" + (" AND kind=?" if kind else "")
        return [dict(t=t, node=n, kind=k, value=v, extra=json.loads(e)) for t, n, k, v, e in
                self.c.execute(q, (run_id, kind) if kind else (run_id,))]

    # ---------------- dataset export ----------------
    def export_csv(self, table, path):
        cols = [d[1] for d in self.c.execute(f"PRAGMA table_info({table})")]
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in self.c.execute(f"SELECT * FROM {table}"):
                w.writerow(r)
        return path

    # ---------------- import of past campaigns ----------------
    def import_campaign(self, json_path, backend, topology="single", protocol="pqsat", note=""):
        """A JSON file written by auth_campaign.py (hardware) or by the emulation tests:
        a list of handshake records, or one record."""
        with open(json_path) as f:
            data = json.load(f)
        recs = data if isinstance(data, list) else [data]
        run_id = "import_" + os.path.basename(json_path).replace(".json", "")
        mode = recs[0].get("mode", "") if recs else ""
        self.start_run(run_id, backend, topology, protocol, "handshake", mode, dict(source=json_path), "import",
                       note)
        for i, r in enumerate(recs):
            self.add_handshake(run_id, r.get("run", i + 1), r)
        good = [r for r in recs if r.get("ok")]
        self.finish_run(run_id, "done", dict(
            runs=len(recs), ok=len(good),
            mean_seconds=round(sum(r["seconds"] for r in good) / len(good), 1) if good else None,
            mean_goodput_Bps=round(sum(r.get("octets_total", 0) / r["seconds"] for r in good) / len(good), 1)
            if good else None))
        return run_id

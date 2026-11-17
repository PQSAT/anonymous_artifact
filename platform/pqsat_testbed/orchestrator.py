"""Constellation orchestrator: drives the platform's nodes from the synchronizer's slot
state, the StarryNet idea with the flight stack underneath.

What it does every slot (default 1 s of emulated time):
    1. positions, links, serving and feeder from Env.slot(t) (orbit.py);
    2. ISL pipes: every pair in the ring gets the slot's propagation delay; pairs whose
       satellites are revoked are closed;
    3. user link and feeder link: attached to the serving and feeder satellites; the link
       model gets the slot's spreading factor and margin (loss follows the margin);
    4. handover: when the synchronizer reports a user handover event, the ground is asked
       for the pre arranged hand over (HANDOVER forwarded to the serving satellite, session
       key over the ISL, user retuned) or, when "method" is "handshake", the user retunes
       and starts a new handshake; the result (time to protected traffic on the new link,
       whether the overlap sufficed) is recorded;
    5. hardware in the loop: the Versal instances are assigned to the satellites the
       manifest's policy names (serving, next, feeder, or fixed names); when the assignment
       changes, the board's instance is retargeted (SCID and keys switch by restarting the
       service with the new node's provisioning bundle, which the registry produced) and the
       emulated node of that satellite is paused;
    6. failures: a node marked "failed" by an experiment stops answering; the synchronizer
       excludes it, the ring routes around it, and the time to restored protected service is
       recorded.

Integration points with the platform core (filled at merge time; each is one call):
    nodes.set_isl_delay(a, b, ms)          emulator backend: per pipe delay
    nodes.set_link_profile(kind, sf, margin) emulator backend: link model parameters
    nodes.move_user(sat_name)              both backends (exists today): retune the user
    nodes.gs.handover(serving_scid, user, target_scid)   terminal library (exists today)
    nodes.pause(sat_name) / nodes.resume(sat_name)       emulator backend
    nodes.retarget_board(board, sat_name)  hardware backend: restart the board's instance as that satellite
Without the core (standalone), the orchestrator produces the same event stream and the
handover plan, which the dashboard shows, and records what it would have done.
"""
from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from . import orbit


class Orchestrator:
    def __init__(self, env, nodes=None, db=None, log: Callable[[str], None] = print, handover_method: str = "prearranged",
                 handover_s: float = 18.7, handshake_s: float = 371.0):
        self.env, self.nodes, self.db, self.log = env, nodes, db, log
        self.method = handover_method
        self.handover_s, self.handshake_s = handover_s, handshake_s
        self.assignment: Dict[str, str] = {}
        self.failed: set = set()
        self.records: List[dict] = []
        self._last_links: Dict[tuple, float] = {}
        self._serving: Optional[str] = None

    # ------------------------------------------------------------------ one slot
    def step(self, t: Optional[float] = None) -> dict:
        s = self.env.slot(t)
        t = s["t"]
        # 2 and 3: links
        for l in s["links"]:
            key = (l["a"], l["b"], l["kind"])
            if l["kind"] == "isl":
                if l["a"] in self.failed or l["b"] in self.failed:
                    continue
                if abs(self._last_links.get(key, -1) - l["delay_ms"]) > 0.05:
                    self._call("set_isl_delay", l["a"], l["b"], l["delay_ms"])
                    self._last_links[key] = l["delay_ms"]
            else:
                sf = int(str(l.get("profile", "SF11")).replace("SF", "") or 11)
                if self._last_links.get(key) != sf:
                    self._call("set_link_profile", l["kind"], sf, l.get("margin_db"))
                    self._last_links[key] = sf
        # 4: handover events from the synchronizer
        for ev in s.get("events", []):
            if ev.get("_done"):
                continue
            ev["_done"] = True
            if ev["kind"] == "handover":
                self._handover(t, ev["frm"], ev["to"], ev.get("overlap_s"))
            elif ev["kind"] == "lost":
                self._record(t, "session_lost", frm=ev.get("frm"), note="no satellite in view; protected service interrupted until the next pass")
            elif ev["kind"] == "acquired":
                self._record(t, "acquired", to=ev.get("to"), note="first satellite of the pass: new handshake")
                self._call("move_user", ev.get("to"))
        # 5: hardware in the loop
        for board, sat in (s.get("hil") or {}).items():
            if self.assignment.get(board) != sat:
                self.assignment[board] = sat
                self._call("retarget_board", board, sat)
                self._record(t, "hil_assignment", board=board, to=sat)
        return s

    def run(self, duration: float, step: float = 1.0, realtime: bool = False, t0: Optional[float] = None) -> List[dict]:
        t = self.env.now() if t0 is None else t0
        end = t + duration
        while t <= end:
            self.step(t)
            t += step
            if realtime:
                time.sleep(step / max(self.env.speed, 1e-6))
        return self.records

    # ------------------------------------------------------------------ actions
    def _handover(self, t: float, frm: str, to: str, overlap: Optional[float] = None):
        if overlap is None:
            u = self.env.sync.users[0] if self.env.sync.users else None
            sp = (float(u["lat"]), float(u["lon"]), float(u.get("alt_km", 0))) if u else None
            overlap = self.env.sync.time_to_set(frm, sp, t) if sp else 0.0
        fits = overlap >= (self.handover_s if self.method == "prearranged" else self.handshake_s)
        t_start = time.time()
        ok = None
        if self.nodes is not None:
            try:
                if self.method == "prearranged":
                    scid = lambda n: next(x["scid"] for x in self.env.sync.sats if x["name"] == n)
                    r = self.nodes.gs.handover(scid(frm), 0x0011, scid(to))
                    up = self.nodes.move_user(to)
                    ok = bool(r) and bool(up)
                else:
                    up = self.nodes.move_user(to)
                    ok = bool(up)                      # the experiment then runs the handshake on the new link
            except Exception as e:
                ok = False
                self.log(f"handover {frm} -> {to} failed: {e}")
        self._record(t, "handover", frm=frm, to=to, method=self.method, overlap_s=round(overlap, 1), fits_overlap=fits,
                     ok=ok, wall_s=round(time.time() - t_start, 1))

    def fail(self, sat: str, t: Optional[float] = None):
        """Experiment hook: a satellite stops (section 7.2 of StarryNet applied to key management)."""
        self.failed.add(sat)
        self.env.sync.sats = [x for x in self.env.sync.sats if x["name"] != sat]
        self._call("pause", sat)
        self._record(t if t is not None else self.env.now(), "failed", frm=sat)

    def restore(self, sat: str, t: Optional[float] = None):
        self.failed.discard(sat)
        self.env.reload()
        self._call("resume", sat)
        self._record(t if t is not None else self.env.now(), "restored", to=sat)

    # ------------------------------------------------------------------ plumbing
    def _call(self, fn: str, *args):
        if self.nodes is not None and hasattr(self.nodes, fn):
            try:
                return getattr(self.nodes, fn)(*args)
            except Exception as e:
                self.log(f"{fn}{args}: {e}")
        else:
            self.log(f"[plan] {fn}{args}")

    def _record(self, t: float, kind: str, **kw):
        row = dict(t=t, kind=kind, **kw)
        self.records.append(row)
        self.log(f"orchestrator t={t:.0f} {kind} {kw}")
        if self.db is not None:
            try:
                self.db.execute("CREATE TABLE IF NOT EXISTS orchestration(t REAL, kind TEXT, detail TEXT)")
                import json
                self.db.execute("INSERT INTO orchestration VALUES(?,?,?)", (t, kind, json.dumps(kw)))
                self.db.commit()
            except Exception:
                pass


def summarise(records: List[dict]) -> dict:
    ho = [r for r in records if r["kind"] == "handover"]
    return dict(handovers=len(ho), fitting=len([r for r in ho if r.get("fits_overlap")]), failed=len([r for r in ho if r.get("ok") is False]),
                sessions_lost=len([r for r in records if r["kind"] == "session_lost"]),
                mean_overlap_s=round(sum(r["overlap_s"] for r in ho) / len(ho), 1) if ho else None)


if __name__ == "__main__":
    import argparse
    from .api_ext import Env
    ap = argparse.ArgumentParser(description="dry run of the orchestrator over the constellation's schedule")
    ap.add_argument("--db", default="testbed.db"); ap.add_argument("--constellation", default="pqsat8")
    ap.add_argument("--hours", type=float, default=24); ap.add_argument("--step", type=float, default=10)
    a = ap.parse_args()
    env = Env(a.db, a.constellation)
    orch = Orchestrator(env, nodes=None, log=lambda s: None)
    recs = orch.run(a.hours * 3600, a.step, t0=0)
    print(summarise(recs))
    for r in recs[:12]:
        print(r)

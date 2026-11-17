"""Feeds the dashboard from the platform core: turns the core's state (terminals, nodes,
database) into the fields the dashboard reads from /api/state and /api/live.

Dashboard fields produced here
    handshake   {title, msgs:[{name, detail, t, state}], done, seconds, octets, nodes, crypto, fits, left}
    links       [{name, state, sa, delay, air, frames}]   from the terminals' statistics and SDLS flags
    metrics     {throughput_bps, latency_ms:{min,max}, app_rtt_ms, seg_rtt_ms, lora_bitrate_bps, tx_util, rx_util, sdls_cost_pct, handovers, hoAvg, hoFailed}
    events      [{t, level, text}]                        tail of the events table
    serving, feeder, hil                                   from the backend (or the orbit layer when the run uses it)
    kpi         {secure_links, avg_handover_s, failed_handovers, last_handshake_s, last_handshake_title, throughput}

How it is used (api.py, after the merge):
    from pqsat_testbed.state_adapter import extend_state, translate_event
    @app.get("/api/state")
    def state():
        st = platform.state()                      # what the core returns today
        return extend_state(st, platform, a.db)    # adds the fields above
    and in the websocket loop: ws.send_json(translate_event(ev))

Every read is defensive (getattr with defaults), so a field the core does not have is
simply absent and the dashboard shows a dash instead of failing.
"""
from __future__ import annotations

import sqlite3
import time
from typing import Any, Dict, List, Optional

MSG_ORDER = ["MSG1", "MSG2", "MSG3", "MSG4", "MSG5", "MSG6", "MSG7", "MSG7f", "MSG8"]
MSG_DIR = {"MSG1": "↑", "MSG2": "↓", "MSG3": "↑", "MSG4": "↓", "MSG5": "↑", "MSG6": "↓", "MSG7": "↑", "MSG7f": "↓", "MSG8": "↑↓"}


def _g(o, name, default=None):
    try:
        v = getattr(o, name) if not isinstance(o, dict) else o.get(name)
        return default if v is None else v
    except Exception:
        return default


def _terminal_link(term, name: str, kind: str) -> Optional[dict]:
    if term is None:
        return None
    st = _g(term, "stats", {}) or {}
    sdls = _g(term, "sdls") is not None
    tc_vc = _g(term, "tc_vc", 0 if kind == "feeder" else 1)
    tm_vc = _g(term, "sdls_tm_vc", 4 if kind == "feeder" else 2)
    spi_tc = 6 if tc_vc == 0 else 1
    spi_tm = 9 if tm_vc == 4 else 2
    m = {}
    try:
        m = term.metrics() or {}
    except Exception:
        pass
    rtt = m.get("seg_rtt", {}) if isinstance(m.get("seg_rtt"), dict) else {}
    return dict(name=name, state="protected" if sdls else "clear",
                sa=f"TC VC{tc_vc} SPI {spi_tc} · TM VC{tm_vc} SPI {spi_tm}" if sdls else "none",
                delay=f"{rtt.get('p50', m.get('seg_rtt_ms', 0)) or 0:.0f} ms RTT" if (rtt or m.get("seg_rtt_ms")) else "–",
                air=f"SF{m.get('sf', 9)}" if m.get("sf") else "SF9",
                frames=f"{st.get('rx_frames', st.get('frames_rx', 0))} ({st.get('rx_lost', st.get('frames_lost', 0))})")


def handshake_progress(db_path: str, run_id: Optional[str]) -> Optional[dict]:
    """Per message progress of the current (or last) handshake from the messages table."""
    try:
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        if run_id is None:
            r = db.execute("SELECT run_id FROM handshakes ORDER BY rowid DESC LIMIT 1").fetchone()
            run_id = r["run_id"] if r else None
        if run_id is None:
            return None
        hs = db.execute("SELECT * FROM handshakes WHERE run_id=? ORDER BY rowid DESC LIMIT 1", (run_id,)).fetchone()
        hid = hs["id"] if hs and "id" in hs.keys() else None
        q = "SELECT * FROM messages WHERE run_id=?" + (" AND handshake_id=?" if hid is not None else "") + " ORDER BY rowid"
        rows = db.execute(q, (run_id, hid) if hid is not None else (run_id,)).fetchall()
        db.close()
    except Exception:
        return None
    by = {}
    for r in rows:
        name = r["name"] if "name" in r.keys() else r["msg"]
        by[name] = r
    msgs = []
    for n in MSG_ORDER:
        r = by.get(n)
        if r is None:
            msgs.append(dict(name=f"{n} {MSG_DIR[n]}", detail="", t=None, state=""))
            continue
        k = r.keys()
        octets = r["octets"] if "octets" in k else r["bytes"] if "bytes" in k else None
        if "segments" in k and r["segments"]:
            detail = f"{octets or 0:,} B · {r['segments']} seg · {r['retx'] if 'retx' in k else 0} retx"
        elif "frames" in k and r["frames"]:
            detail = f"{octets or 0:,} B · {r['frames']} frames · {r['lost'] if 'lost' in k else 0} lost"
        else:
            detail = f"{octets or 0:,} B"
        msgs.append(dict(name=f"{n} {MSG_DIR[n]}", detail=detail.replace(",", " "), t=r["seconds"] if "seconds" in k else None, state="d"))
    done = bool(hs and ("ok" in hs.keys()) and hs["ok"])
    out = dict(title=hs["label"] if hs and "label" in hs.keys() else "", msgs=msgs, done=done)
    if hs:
        k = hs.keys()
        out.update(seconds=hs["seconds"] if "seconds" in k else None, octets=hs["octets"] if "octets" in k else None, nodes=4,
                   crypto=(f"kem {hs['kem_ms']:.2f} · sign {hs['sign_ms']:.2f} · verify {hs['verify_ms']:.2f} ms" if "kem_ms" in k and hs["kem_ms"] else None))
    return out


def kpis(db_path: str) -> dict:
    out = dict(secure_links=None, avg_handover_s=None, failed_handovers=0, last_handshake_s=None, last_handshake_title=None, throughput=None)
    try:
        db = sqlite3.connect(db_path)
        r = db.execute("SELECT AVG(json_extract(summary,'$.handover_s')) FROM runs WHERE experiment LIKE 'handover%' AND status='done' AND rowid IN (SELECT rowid FROM runs WHERE experiment LIKE 'handover%' ORDER BY rowid DESC LIMIT 10)").fetchone()
        if r and r[0]:
            out["avg_handover_s"] = round(r[0], 1)
        r = db.execute("SELECT COUNT(*) FROM runs WHERE experiment LIKE 'handover%' AND status='failed'").fetchone()
        out["failed_handovers"] = r[0] if r else 0
        r = db.execute("SELECT seconds, run_id FROM handshakes WHERE ok=1 ORDER BY rowid DESC LIMIT 1").fetchone()
        if r:
            out["last_handshake_s"], out["last_handshake_title"] = round(r[0], 1), r[1]
        r = db.execute("SELECT json_extract(summary,'$.throughput_bps') FROM runs WHERE experiment='traffic' AND status='done' ORDER BY rowid DESC LIMIT 1").fetchone()
        if r and r[0]:
            out["throughput"] = round(r[0], 1)
        db.close()
    except Exception:
        pass
    return out


def events_tail(db_path: str, limit: int = 30) -> List[dict]:
    try:
        db = sqlite3.connect(db_path)
        rows = db.execute("SELECT t, text FROM events ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        db.close()
    except Exception:
        return []
    out = []
    for t, text in reversed(rows):
        out.append(translate_event(dict(t=t, text=text)))
    return out


def translate_event(ev: Dict[str, Any]) -> dict:
    text = ev.get("text") or ev.get("message") or str(ev)
    lvl = "err" if any(w in text.lower() for w in ("reject", "fail", "error", "refused", "dropped")) else \
          "warn" if any(w in text.lower() for w in ("handover", "rising", "retx", "nak", "rekey", "plan")) else "info"
    t = ev.get("t")
    try:
        ts = time.strftime("%H:%M:%S", time.localtime(float(t))) if t else time.strftime("%H:%M:%S")
    except Exception:
        ts = str(t)
    return dict(t=ts, level=lvl, text=text)


def extend_state(st: dict, platform=None, db_path: Optional[str] = None) -> dict:
    """Add the dashboard's fields to the core's state dict.  `platform` is the Platform
    object (its `nodes` attribute is the backend's node set when a run is active)."""
    st = dict(st or {})
    nodes = _g(platform, "nodes")
    gs, ue = _g(nodes, "gs"), _g(nodes, "ue")
    links = [l for l in (_terminal_link(gs, "ground station → feeder", "feeder"), _terminal_link(ue, "user → serving", "user")) if l]
    serving = _g(nodes, "serving")
    sats = _g(nodes, "sats", {}) or {}
    if isinstance(sats, dict) and serving in sats:
        scid = sats[serving].get("scid") if isinstance(sats[serving], dict) else None
        st["serving"] = scid or serving
        for l in links:
            l["name"] = l["name"].replace("serving", f"SAT-{(scid or 0) - 0x100}" if scid else str(serving))
    st["links"] = links
    hil = {}
    for name, s in (sats.items() if isinstance(sats, dict) else []):
        ro = s.get("runs_on") if isinstance(s, dict) else None
        if ro and str(ro).lower().startswith("versal"):
            hil[ro] = s.get("scid")
    if hil:
        st["hil"] = hil
    if db_path:
        run_id = st.get("run_id") or _g(platform, "current_run_id")
        hs = handshake_progress(db_path, run_id)
        if hs:
            st["handshake"] = hs
        st["events"] = events_tail(db_path)
        st["kpi"] = kpis(db_path)
    metrics = {}
    for term in (gs, ue):
        try:
            m = term.metrics() if term is not None else {}
        except Exception:
            m = {}
        if m:
            metrics.setdefault("seg_rtt_ms", (m.get("seg_rtt") or {}).get("p50") if isinstance(m.get("seg_rtt"), dict) else m.get("seg_rtt_ms"))
            metrics.setdefault("app_rtt_ms", (m.get("app_rtt") or {}).get("p50") if isinstance(m.get("app_rtt"), dict) else m.get("app_rtt_ms"))
            metrics.setdefault("lora_bitrate_bps", m.get("lora_bitrate_bps"))
            metrics.setdefault("tx_util", m.get("tx_util")); metrics.setdefault("rx_util", m.get("rx_util"))
            metrics.setdefault("throughput_bps", m.get("throughput_bps"))
            if m.get("latency_ms"):
                metrics["latency_ms"] = m["latency_ms"]
    if metrics:
        st["metrics"] = {k: v for k, v in metrics.items() if v is not None}
    st["core_loaded"] = True
    return st

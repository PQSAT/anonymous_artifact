"""N handshakes of a protocol; the record of each, the four network metrics around each
and the session key agreement."""
import time

from pqsat_testbed.plugins import Experiment, PROTOCOLS


class Handshakes(Experiment):
    name = "handshake"
    description = "Run N handshakes of a protocol and record every message, frame and metric"

    def run(self, platform, nodes, db, run_id, live, protocol="pqsat", runs=1, mode="ref", **opts):
        proto = PROTOCOLS[protocol]()
        recs = []
        for i in range(int(runs)):
            live(dict(event="handshake_start", n=i + 1, of=int(runs)))
            t0 = time.time()
            m0 = {n: len(s["sim"].log) for n, s in nodes.sats.items() if s["sim"] is not None}
            rec = proto.run(platform, nodes, mode=mode, **opts)
            rec["run"] = i + 1
            rec["started"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t0))
            metrics = dict(user=nodes.ue.metrics(since=t0), ground=nodes.gs.metrics(since=t0))
            metrics["goodput_Bps"] = round(rec.get("octets_total", 0) / rec["seconds"], 2) if rec.get("seconds") else None
            metrics["isl_frames"] = {n: s["sim"].isl_frames_tx for n, s in nodes.sats.items() if s["sim"] is not None}
            rec["metrics"] = metrics
            db.add_handshake(run_id, i + 1, rec, metrics)
            for n, s in nodes.sats.items():
                if s["sim"] is not None:
                    db.add_events(run_id, n, s["sim"].log[m0[n]:], s["sim"].log_t[m0[n]:])
            recs.append(rec)
            live(dict(event="handshake_done", n=i + 1, ok=rec.get("ok"), seconds=rec.get("seconds"),
                      metrics=metrics))
        db.add_terminal_samples(run_id, "ue", nodes.ue.samples)
        db.add_terminal_samples(run_id, "gs", nodes.gs.samples)
        good = [r for r in recs if r.get("ok")]
        return dict(runs=len(recs), ok=len(good),
                    mean_seconds=round(sum(r["seconds"] for r in good) / len(good), 1) if good else None,
                    mean_goodput_Bps=round(sum(r["metrics"]["goodput_Bps"] for r in good) / len(good), 1) if good else None,
                    records=[dict(run=r["run"], ok=r.get("ok"), seconds=r.get("seconds"),
                                  octets=r.get("octets_total"), segments=r.get("uplink_segments"),
                                  retx=r.get("uplink_retransmissions"), frames=r.get("downlink_frames"),
                                  lost=r.get("downlink_lost")) for r in recs])

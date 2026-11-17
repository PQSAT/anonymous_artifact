"""Prediction experiment (the StarRTT idea on our link): from the records in the
database, learn to forecast (a) the link RTT of the next segments from the recent RTT
history, and (b) the completion time of a handshake from its first messages, then report
the error on held out runs.  Pure numpy gradient boosting is heavy, so this uses
scikit-learn when present and falls back to a ridge regression in numpy.

    params: horizon (segments ahead, default 10), min_samples (default 200)
"""
import numpy as np

from pqsat_testbed.plugins import Experiment


def _fit(X, y):
    try:
        from sklearn.ensemble import GradientBoostingRegressor
        m = GradientBoostingRegressor(n_estimators=200, max_depth=3, learning_rate=0.05)
        m.fit(X, y)
        return m.predict
    except Exception:
        Xb = np.hstack([X, np.ones((len(X), 1))])
        w = np.linalg.solve(Xb.T @ Xb + 1e-3 * np.eye(Xb.shape[1]), Xb.T @ y)
        return lambda Z: np.hstack([Z, np.ones((len(Z), 1))]) @ w


class Predict(Experiment):
    name = "predict"
    description = "Forecast link RTT over the next segments and handshake completion time from the recorded runs"
    needs_nodes = False

    def run(self, platform, nodes, db, run_id, live, horizon=10, min_samples=200, **_):
        c = db.c
        # ---- (a) link RTT forecast: features = last 5 RTTs, bytes; target = mean RTT of the next `horizon`
        rows = c.execute("SELECT run_id, node, t, value, extra FROM samples WHERE kind='seg_rtt' ORDER BY run_id, node, t").fetchall()
        import json
        series = {}
        for rid, node, t, v, extra in rows:
            series.setdefault((rid, node), []).append((t, v, json.loads(extra).get("bytes", 255)))
        X, y, groups = [], [], []
        for key, s in series.items():
            vals = [v for _, v, _ in s]
            for i in range(5, len(vals) - int(horizon)):
                X.append(vals[i - 5:i] + [s[i][2]])
                y.append(float(np.mean(vals[i:i + int(horizon)])))
                groups.append(key[0])
        res = dict(rtt=dict(samples=len(X)))
        if len(X) >= int(min_samples):
            X, y, groups = np.array(X), np.array(y), np.array(groups)
            runs = sorted(set(groups))
            test_runs = set(runs[::4])          # every fourth run held out
            tr, te = np.array([g not in test_runs for g in groups]), np.array([g in test_runs for g in groups])
            if te.sum() and tr.sum():
                pred = _fit(X[tr], y[tr])
                err = np.abs(pred(X[te]) - y[te])
                base = np.abs(X[te][:, 4] - y[te])    # naive: last value
                res["rtt"].update(train=int(tr.sum()), test=int(te.sum()), mae_ms=round(float(err.mean()), 1),
                                  naive_mae_ms=round(float(base.mean()), 1), horizon_segments=int(horizon))
        # ---- (b) handshake completion time from the first two messages
        hs = c.execute("SELECT run_id, seconds, octets, up_segments, up_retx, down_frames, down_lost, record FROM handshakes "
                       "WHERE ok=1 AND seconds IS NOT NULL").fetchall()
        X2, y2 = [], []
        for rid, sec, octets, segs, retx, frames, lost, rec in hs:
            r = json.loads(rec)
            ms = r.get("messages", [])
            if len(ms) < 2:
                continue
            m1, m2 = ms[0], ms[1]
            X2.append([m1.get("octets", 0), m1.get("seconds", 0), m1.get("retransmissions", 0), m2.get("octets", 0),
                       m2.get("seconds", 0), m2.get("lost", 0), 1.0 if r.get("mode") == "full" else 0.0])
            y2.append(sec)
        res["handshake"] = dict(samples=len(X2))
        if len(X2) >= 8:
            X2, y2 = np.array(X2), np.array(y2)
            idx = np.arange(len(X2))
            te = idx % 4 == 0
            pred = _fit(X2[~te], y2[~te])
            err = np.abs(pred(X2[te]) - y2[te])
            res["handshake"].update(train=int((~te).sum()), test=int(te.sum()), mae_s=round(float(err.mean()), 1),
                                    mean_seconds=round(float(y2.mean()), 1))
        live(dict(event="prediction", **res))
        return res

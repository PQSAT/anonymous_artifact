"""Handover: the user in session with its serving satellite retunes to the other
satellite and authenticates there.  Constellation topology only.  Records both
handshakes and the handover time (retune to protected traffic on the new link)."""
import time

from pqsat_testbed.plugins import Experiment, PROTOCOLS


class Handover(Experiment):
    name = "handover"
    description = "User moves from its serving satellite to the other one; cost = one handshake"

    def run(self, platform, nodes, db, run_id, live, protocol="pqsat", mode="ref", **opts):
        if nodes.topology != "constellation":
            return dict(error="handover needs the constellation topology")
        proto = PROTOCOLS[protocol]()
        a = proto.run(platform, nodes, mode=mode, **opts)
        a["run"] = 1
        db.add_handshake(run_id, 1, a)
        live(dict(event="handshake_done", n=1, ok=a.get("ok"), seconds=a.get("seconds"), serving=nodes.serving))
        other = {"sat2": "sat1", "sat3": "sat2", "sat1": "sat2"}[nodes.serving]
        t_ho = time.time()
        up = nodes.move_user(other)
        live(dict(event="retuned", to=other, link_up=up))
        b = proto.run(platform, nodes, mode=mode, **opts) if up else dict(ok=False, error="new link did not come up")
        b["run"] = 2
        db.add_handshake(run_id, 2, b)
        ho = time.time() - t_ho
        ok = b.get("ok") and nodes.ue.send_message(0x0001, "after handover")
        end = time.time() + 30
        while ok and time.time() < end and not any("after handover" in m["text"] for m in nodes.gs.inbox):
            time.sleep(0.3)
        db.add_sample(run_id, "ue", "handover_s", ho, t=t_ho, to=other)
        db.add_terminal_samples(run_id, "ue", nodes.ue.samples)
        db.add_terminal_samples(run_id, "gs", nodes.gs.samples)
        return dict(first=dict(serving=a.get("serving_satellite"), ok=a.get("ok"), seconds=a.get("seconds")),
                    second=dict(serving=b.get("serving_satellite"), ok=b.get("ok"), seconds=b.get("seconds")),
                    keys_differ=a.get("sk_user") != b.get("sk_user"), handover_seconds=round(ho, 1),
                    traffic_after=bool(ok))

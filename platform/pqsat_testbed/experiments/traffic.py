"""Traffic after (or without) a handshake: throughput, one way latency, application RTT
and bandwidth utilisation on the user to ground path through the constellation.

    messages   number of user to ground messages
    size       octets per message (text payload)
    pings      ground PINGs for application RTT
    protected  run a handshake first so the traffic goes under SDLS
"""
import time

from pqsat_testbed.plugins import Experiment, PROTOCOLS


class Traffic(Experiment):
    name = "traffic"
    description = "User to ground messages and ground PINGs: throughput, latency, RTT, bandwidth"

    def run(self, platform, nodes, db, run_id, live, protocol="pqsat", messages=5, size=120, pings=5,
            protected=False, mode="ref", **opts):
        summary = {}
        if protected:
            rec = PROTOCOLS[protocol]().run(platform, nodes, mode=mode, **opts)
            db.add_handshake(run_id, 0, rec)
            summary["handshake_ok"] = rec.get("ok")
            live(dict(event="handshake_done", n=0, ok=rec.get("ok"), seconds=rec.get("seconds")))
        t0 = time.time()
        lat = []
        delivered = 0
        for i in range(int(messages)):
            text = f"m{i:04d}:" + "x" * max(0, int(size) - 6)
            ts = time.time()
            ok = nodes.ue.send_message(0x0001, text)
            end = time.time() + 60
            got = None
            while time.time() < end:
                for m in nodes.gs.inbox:
                    if m["text"].startswith(f"m{i:04d}:"):
                        got = m
                        break
                if got:
                    break
                time.sleep(0.2)
            if got:
                delivered += 1
                ms = (time.time() - ts) * 1e3
                lat.append(ms)
                db.add_sample(run_id, "ue>gs", "latency", ms, t=ts, bytes=len(text) + 4, accepted=ok)
                live(dict(event="message", n=i + 1, latency_ms=round(ms), ok=True))
            else:
                live(dict(event="message", n=i + 1, ok=False))
        el = time.time() - t0
        rtts = []
        for i in range(int(pings)):
            r = nodes.gs.ping()
            s = [x for x in nodes.gs.samples if x["kind"] == "app_rtt"]
            if r == "OK" and s:
                rtts.append(s[-1]["ms"])
            live(dict(event="ping", n=i + 1, result=r))
        db.add_terminal_samples(run_id, "ue", nodes.ue.samples)
        db.add_terminal_samples(run_id, "gs", nodes.gs.samples)
        summary.update(
            messages=int(messages), delivered=delivered, payload_octets=int(size),
            throughput_Bps=round(delivered * (int(size) + 4) / el, 2) if el else None,
            latency_ms=dict(count=len(lat), min=round(min(lat)), mean=round(sum(lat) / len(lat)), max=round(max(lat)))
            if lat else dict(count=0),
            app_rtt_ms=dict(count=len(rtts), mean=round(sum(rtts) / len(rtts)) if rtts else None),
            user=nodes.ue.metrics(since=t0), ground=nodes.gs.metrics(since=t0), seconds=round(el, 1),
            protected=bool(protected))
        return summary

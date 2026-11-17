"""Pre arranged handover over the ISL, against the handshake handover.

The user is in session with SAT-2.  The ground gives SAT-2, through SAT-1 over the ISL, a
hand over order carrying a MAC under a key derived from this user's own session key (only
the ground station of this session can give it).  SAT-2 transfers a derived next link key to
SAT-1 end to end (ML-KEM to SAT-1, signed by SAT-2; a relay cannot open it) and erases its
own copy.  The user retunes to SAT-1 and continues under SDLS with that derived key, no new
handshake.  Measured: the forwarded command's round trip, the time from the
handover command to the first protected message delivered on the new link, and the same
figure for the handshake handover for comparison.  Constellation topology, emulator or
hardware.
"""
import time

from pqsat_testbed.plugins import Experiment, PROTOCOLS


class HandoverPrearranged(Experiment):
    name = "handover_prearranged"
    description = "Session key handed SAT-2 to SAT-1 over the ISL on a ground command; user retunes with no new handshake"

    def run(self, platform, nodes, db, run_id, live, protocol="pqsat", mode="ref", **opts):
        if nodes.topology not in ("constellation", "chain"):
            return dict(error="needs the constellation or chain topology")
        proto = PROTOCOLS[protocol]()
        a = proto.run(platform, nodes, mode=mode, **opts)
        a["run"] = 1
        db.add_handshake(run_id, 1, a)
        live(dict(event="handshake_done", n=1, ok=a.get("ok"), seconds=a.get("seconds"), serving=nodes.serving))
        if not a.get("ok"):
            return dict(error="first handshake failed")
        sk = bytes.fromhex(a["sk_user"])
        hardware = getattr(nodes, "backend", "") == "hardware"
        if hardware:
            # keep the ground link key where the stale link clearing looks for it (gs/auth_hw_*.json)
            try:
                import json, os
                from pqsat_testbed import paths
                with open(os.path.join(paths.REL, "gs", "auth_hw_platform_keys.json"), "w") as kf:
                    json.dump([dict(ok=True, sk_ground=a.get("sk_ground") or a["sk_user"])], kf)
            except Exception:
                pass
            # The feeder keys the ground link only when the whole key transfer has crossed the radio
            # inter satellite link (about 40 s).  A protected command sent before that is not understood.
            t_key = time.time()
            for _ in range(30):
                if nodes.gs.command(0x01) == "OK":
                    break
            live(dict(event="ground_link_keyed", after_s=round(time.time() - t_key, 1)))
            db.add_sample(run_id, "gs", "ground_link_keyed_s", round(time.time() - t_key, 1))
        sim1 = nodes.sats["sat1"]["sim"]
        mark = 0
        # one forwarded PING first: the commanding path SAT-1 -> ISL -> SAT-2 and its acknowledgement
        t0 = time.time()
        serving_scid = nodes.sats[nodes.serving]["scid"]
        target = {"sat2": "sat1", "sat3": "sat2"}[nodes.serving]
        r_ping = nodes.gs.forward_command(serving_scid, 0x01)
        fwd_rtt = round((time.time() - t0) * 1e3)
        live(dict(event="forwarded_ping", result=r_ping, rtt_ms=fwd_rtt))
        db.add_sample(run_id, "gs", "forwarded_cmd_rtt", fwd_rtt, cmd="PING", result=r_ping)
        # the handover command, forwarded to the serving satellite
        t_ho = time.time()
        r_ho = nodes.gs.handover(serving_scid, 0x0011, nodes.sats[target]["scid"], sk)
        live(dict(event="handover_command", result=r_ho))
        keyed = False
        if sim1 is not None:
            end = time.time() + 15
            while time.time() < end and not keyed:
                keyed = any("taken over from SAT" in l for l in nodes.sats[target]["sim"].log[mark:])
                time.sleep(0.2)
        # the user retunes to SAT-1 and keys its new terminal with the same session key
        up = nodes.move_user(target)
        live(dict(event="retuned", to=target, link_up=up))
        if up:
            import pqsat_proto as P
            nodes.ue.sdls_start(P.next_link_key(sk, nodes.sats[target]["scid"]))   # derived key, not the session key
        # the next satellite keys the user link once the whole key transfer has arrived, so on a radio
        # inter satellite link the first tries can be early: try again until the message arrives
        delivered = False
        for attempt in range(6 if hardware else 1):
            ok = up and nodes.ue.send_message(0x0001, "after prearranged handover")
            end = time.time() + (20 if hardware else 40)
            while ok and time.time() < end and not any("after prearranged handover" in m["text"] for m in nodes.gs.inbox):
                time.sleep(0.3)
            delivered = any("after prearranged handover" in m["text"] for m in nodes.gs.inbox)
            if delivered or not up:
                break
            nodes.ue.init_cop()
        ho = round(time.time() - t_ho, 1)
        db.add_sample(run_id, "ue", "handover_prearranged_s", ho, t=t_ho, delivered=delivered)
        for n, sdict in nodes.sats.items():
            if sdict["sim"] is not None:
                db.add_events(run_id, n, sdict["sim"].log, sdict["sim"].log_t)
        db.add_terminal_samples(run_id, "ue", nodes.ue.samples)
        db.add_terminal_samples(run_id, "gs", nodes.gs.samples)
        return dict(first_handshake_seconds=a.get("seconds"), forwarded_ping=r_ping, forwarded_cmd_rtt_ms=fwd_rtt,
                    handover_command=r_ho, sat1_keyed_user_link=keyed, link_up=up,
                    protected_message_delivered=delivered, handover_seconds=ho,
                    handshake_handover_seconds_for_comparison=a.get("seconds"))

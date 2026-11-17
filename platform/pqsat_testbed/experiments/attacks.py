"""Attack suite: the handshake attacks against the flight satellite code with a live
handshake in progress, then the SDLS attacks on the protected link.  Emulator only (the
adversary is a terminal on the user's channel; on the hardware this is the third T-Beam,
to be run by hand when approved).  Reference mode, post quantum protocol."""
import time

from pqsat_testbed import paths  # noqa: F401
from pqsat_testbed.plugins import Experiment, ATTACKS
import pqsat_proto as P
from handshake_runner import load_bundle, ID_GS, ID_UE
from pqsat_roles import UserSession, GroundSession


class AttackSuite(Experiment):
    name = "attacks"
    description = "Replay, forged MSG3, junk MSG1, stale MSG1 against a live handshake; clear, replayed and flipped frames under SDLS"

    def run(self, platform, nodes, db, run_id, live, **_):
        if nodes.adversary is None:
            return dict(error="attacks need the emulator (adversary terminal)")
        sat = nodes.serving
        sat_id = nodes.sats[sat]["scid"]
        adv = nodes.adversary
        b_ue, b_gs, b_sat = load_bundle("ue1"), load_bundle("gs"), load_bundle(sat)
        u, g = UserSession(b_ue, full_certs=False), GroundSession(b_gs, full_certs=False)
        u.cache[sat_id], u.cache[ID_GS] = b_sat["cert"], b_gs["cert"]
        g.cache[sat_id], g.cache[ID_UE] = b_sat["cert"], b_ue["cert"]
        results = []

        def recv(term, types, timeout=240):
            end = time.time() + timeout
            while time.time() < end:
                r = term.wait_auth(min(5.0, end - time.time()))
                if r and r[1][1] in types:
                    return r[1]
            return None

        # ---- a live handshake, attacked between MSG2 and MSG3 ----
        msg1 = u.start(sat_id, ID_GS)[0][1]
        nodes.ue.send_auth(sat_id, msg1)
        m2 = recv(nodes.gs, (P.MSG2,))
        msg3 = g.handle(m2)[0][1]
        # all four handshake attacks while the handshake is live and the link is still in clear
        for name, kw in (("junk_msg1", dict(captured_msg1=msg1)), ("forged_msg3", dict(genuine_msg3=msg3)),
                         ("replay_msg1", dict(captured_msg1=msg1)), ("stale_msg1", {})):
            r = ATTACKS[name]().run(platform, nodes, adv, **kw)
            results.append(r)
            live(dict(event="attack", **{k: v for k, v in r.items() if k != "evidence"}))
        # the genuine handshake continues
        nodes.gs.send_auth(sat_id, msg3)
        m4 = recv(nodes.ue, (P.MSG4,))
        survived = m4 is not None
        if survived:
            nodes.ue.send_auth(sat_id, u.handle(m4)[0][1])
            m6 = recv(nodes.gs, (P.MSG6,))
            nodes.gs.send_auth(sat_id, g.handle(m6)[0][1])
            m7 = recv(nodes.ue, (P.MSG7_FWD,))
            nodes.ue.send_auth(sat_id, u.handle(m7)[0][1])
            m8 = recv(nodes.gs, (P.MSG8,))
            g.handle(m8)
            survived = u.sk is not None and u.sk == g.sk
        live(dict(event="attack", name="live handshake survived", ok=survived))
        results.append(dict(name="live_handshake_survived", ok=survived))
        # ---- SDLS attacks: key the links first ----
        nodes.ue.sdls_start(u.sk)
        nodes.gs.sdls_start(g.sk)
        sim = nodes.sats[sat]["sim"]
        end = time.time() + 25
        while time.time() < end and not any("transmit association started on TM VC2" in l for l in sim.log):
            time.sleep(0.5)
        # capture one protected uplink frame by sending a message
        captured = {}
        orig = sim.uplink

        def tap(frame):
            if not (frame[0] & 0x10) and frame[6:8] == b"\x00\x01":
                captured["f"] = bytes(frame)
            return orig(frame)

        sim.uplink = tap
        nodes.ue.send_message(ID_GS, "protected probe")
        time.sleep(4)
        sim.uplink = orig
        for name, kw in (("sdls_clear", {}), ("sdls_replay", dict(captured_frame=captured.get("f"))),
                         ("sdls_flip", dict(captured_frame=captured.get("f")))):
            if "captured_frame" in kw and kw["captured_frame"] is None:
                results.append(dict(name=name, error="no protected frame captured"))
                continue
            r = ATTACKS[name]().run(platform, nodes, adv, **kw)
            results.append(r)
            live(dict(event="attack", **{k: v for k, v in r.items() if k != "evidence"}))
        still = nodes.ue.send_message(ID_GS, "still here")
        time.sleep(8)
        still = still and any("still here" in m["text"] for m in nodes.gs.inbox)
        results.append(dict(name="user_still_works_under_sdls", ok=still))
        db.add_events(run_id, sat, sim.log, sim.log_t)
        rejected = sum(1 for r in results if r.get("rejected_by"))
        attacks = sum(1 for r in results if "rejected_by" in r)
        return dict(attacks=attacks, rejected=rejected, live_handshake_survived=survived, user_still_works=still,
                    results=results)

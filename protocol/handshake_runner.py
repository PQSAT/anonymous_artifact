"""Run the three party handshake over a link and measure it.

This is the first form of the emulator API.  The same code drives the emulated
link (the real satellite core as a process) and the real radio (the bridge and
the T-Beams); only the Terminal objects differ.

    from handshake_runner import run_handshake
    result = run_handshake(ue_terminal, gs_terminal, mode="full")

The result carries, per message and in total: octets, uplink segments, COP-1
acknowledgement round trips, retransmissions, downlink frames, wall clock, and
the primitive timings each role recorded.
"""
import os
import pickle
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pqsat_proto as P                                   # noqa: E402
from pqsat_roles import UserSession, GroundSession, HandshakeFailed  # noqa: E402

ID_GS, ID_UE, ID_SAT = 0x0001, 0x0011, 0x0101
KEYS = os.path.join(HERE, "keys")

MSG_NAMES = {P.MSG1: "MSG1", P.MSG2: "MSG2", P.MSG3: "MSG3", P.MSG4: "MSG4", P.MSG5: "MSG5", P.MSG6: "MSG6",
             P.MSG7: "MSG7", P.MSG7_FWD: "MSG7f", P.MSG8: "MSG8", P.MSG8_FWD: "MSG8", P.DEMAND: "DEMAND"}


def load_bundle(name):
    with open(os.path.join(KEYS, name + ".pickle"), "rb") as f:
        return pickle.load(f)


class _Stats:
    """Snapshot a terminal's link statistics so per message deltas can be taken."""

    def __init__(self, term):
        self.t = term

    def snap(self):
        s = self.t.stats
        return dict(tc=s["tc_frames"], retx=s["tc_retx"], tm=s["tm_frames"], lost=s["tm_lost"],
                    naks=s.get("naks", 0), repaired=s.get("chunks_repaired", 0))

    @staticmethod
    def delta(a, b):
        return {k: b[k] - a[k] for k in a}


def run_handshake(ue_term, gs_term, mode="full", preload=True, timeout=1800.0, verbose=True, sdls=True,
                  sat="sat1", sat_id=ID_SAT):
    """Drive one handshake.  ue_term and gs_term are ccsds_link.Terminal objects
    already started and with COP-1 initialised.  Returns a result dict.
    With sdls, each terminal keys its SDLS security associations from the session
    key at the end (the satellite does the same on MSG8), so every frame after the
    handshake is protected by CCSDS 355.0."""
    b_ue, b_gs, b_sat = load_bundle("ue1"), load_bundle("gs"), load_bundle(sat)
    full = (mode == "full")
    ue, gs = UserSession(b_ue, full_certs=full), GroundSession(b_gs, full_certs=full)
    ue.install_cert(b_sat["cert"])
    if preload:
        ue.install_cert(b_gs["cert"])
        gs.install_cert(b_sat["cert"])
        gs.install_cert(b_ue["cert"])
    ue_term.auth_rx.clear()
    gs_term.auth_rx.clear()
    su, sg = _Stats(ue_term), _Stats(gs_term)

    per_msg = []
    t_start = time.time()

    def send(term, snapper, dst_role, msg):
        """Send one message up through the satellite and record what it cost."""
        dst = sat_id
        before = snapper.snap()
        t0 = time.time()
        ok = term.send_auth(dst, msg)
        dt = time.time() - t0
        d = _Stats.delta(before, snapper.snap())
        rec = dict(msg=MSG_NAMES.get(msg[1], hex(msg[1])), direction="up", octets=len(msg),
                   segments=d["tc"], retransmissions=d["retx"], rtts=d["tc"], seconds=round(dt, 3), ok=ok)
        per_msg.append(rec)
        if verbose:
            print(f"   {rec['msg']:6s} up   {len(msg):6d} B  {d['tc']:3d} segments  {d['retx']} retx  {dt:6.1f} s",
                  flush=True)
        if not ok:
            raise HandshakeFailed(f"{rec['msg']} not acknowledged by the satellite")

    def recv(term, snapper, expect_types):
        before = snapper.snap()
        t0 = time.time()
        while True:
            left = timeout - (time.time() - t_start)
            if left <= 0:
                raise HandshakeFailed("timeout waiting for " + "/".join(MSG_NAMES[t] for t in expect_types))
            r = term.wait_auth(min(left, 5.0))
            if r is None:
                continue
            src, msg = r
            if msg[1] in expect_types:
                break
        dt = time.time() - t0
        d = _Stats.delta(before, snapper.snap())
        rec = dict(msg=MSG_NAMES.get(msg[1], hex(msg[1])), direction="down", octets=len(msg),
                   frames=d["tm"], lost=d["lost"], naks=d["naks"], repaired=d["repaired"], seconds=round(dt, 3))
        per_msg.append(rec)
        if verbose:
            print(f"   {rec['msg']:6s} down {len(msg):6d} B  {d['tm']:3d} frames    {d['lost']} lost  "
                  f"{d['naks']} NAK {d['repaired']} repaired  {dt:6.1f} s", flush=True)
        return msg

    # ---- the handshake, message by message ----
    out = ue.start(sat_id, ID_GS)
    send(ue_term, su, "sat", out[0][1])                                   # MSG1

    while True:                                                            # satellite -> ground
        m = recv(gs_term, sg, (P.MSG2,))
        out = gs.handle(m)
        if out and out[0][1][1] == P.DEMAND:
            send(gs_term, sg, "sat", out[0][1]); continue
        break
    send(gs_term, sg, "sat", out[0][1])                                    # MSG3

    while True:                                                            # satellite -> user
        m = recv(ue_term, su, (P.MSG4, P.DEMAND))
        if m[1] == P.DEMAND:                                               # satellite lacks our certificate
            ue.full_certs = True
            send(ue_term, su, "sat", ue.start(sat_id, ID_GS)[0][1]); continue
        out = ue.handle(m)
        if out and out[0][1][1] == P.DEMAND:
            send(ue_term, su, "sat", out[0][1]); continue
        break
    send(ue_term, su, "sat", out[0][1])                                    # MSG5

    m = recv(gs_term, sg, (P.MSG6,))
    out = gs.handle(m)
    send(gs_term, sg, "sat", out[0][1])                                    # MSG7

    m = recv(ue_term, su, (P.MSG7_FWD,))
    out = ue.handle(m)
    send(ue_term, su, "sat", out[0][1])                                    # MSG8
    if sdls and ue.sk is not None:
        ue_term.sdls_start(ue.sk)              # the user's MSG8 is acknowledged: key its link now

    m = recv(gs_term, sg, (P.MSG8_FWD,))   # tag_u' with the satellite's tag_s
    gs.handle(m)
    if sdls and gs.sk is not None:
        # the ground has seen MSG8 with the satellite's tag_s: key its link now.  The ground link
        # runs under the derived ground link key; SK itself never leaves the serving satellite
        gs_term.sdls_start(P.ground_link_key(gs.sk))

    total = time.time() - t_start
    ok = ue.sk is not None and ue.sk == gs.sk
    result = dict(
        mode=mode, ok=ok, seconds=round(total, 3),
        sk_user=ue.sk.hex() if ue.sk else None, sk_ground=P.ground_link_key(gs.sk).hex() if gs.sk else None,
        sk_session=gs.sk.hex() if gs.sk else None,
        octets_total=sum(r["octets"] for r in per_msg),
        uplink_segments=sum(r.get("segments", 0) for r in per_msg),
        uplink_retransmissions=sum(r.get("retransmissions", 0) for r in per_msg),
        downlink_frames=sum(r.get("frames", 0) for r in per_msg),
        downlink_lost=sum(r.get("lost", 0) for r in per_msg),
        downlink_naks=sum(r.get("naks", 0) for r in per_msg),
        downlink_repaired=sum(r.get("repaired", 0) for r in per_msg),
        messages=per_msg,
        sdls=dict(user=ue_term.stats.get("sdls_tc_sent", 0) is not None and ue_term.sdls is not None,
                  ground=gs_term.sdls is not None),
        user_timing_ms={k: round(v * 1e3, 3) for k, v in ue.timing.items()},
        ground_timing_ms={k: round(v * 1e3, 3) for k, v in gs.timing.items()},
    )
    if verbose:
        print(f"   total {result['octets_total']} B, {result['uplink_segments']} uplink segments "
              f"({result['uplink_retransmissions']} retx), {result['downlink_frames']} downlink frames "
              f"({result['downlink_lost']} lost), {total:.1f} s, keys agree: {ok}", flush=True)
    return result

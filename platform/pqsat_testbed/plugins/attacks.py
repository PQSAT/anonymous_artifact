"""Attack plug ins: what an adversary with a radio on the user's channel can do.  Each
takes the adversary terminal (a Terminal on the serving satellite's channel with the
user's identity and the COP-1 sequence number it has observed) and returns the evidence:
whether the link layer accepted the frame and what the satellite did with it.

These are the attacks of the emulation evidence (test_attacks.py, test_sdls_link.py):
    replay_msg1      a captured MSG1 sent again inside the freshness window
    forged_msg3      a MSG3 with one bit flipped in the ground's signature, during a live handshake
    junk_msg1        an MSG1 shaped message with a changed nonce, during a live handshake
    stale_msg1       a MSG1 older than the freshness window
    sdls_clear       a clear frame on a protected channel
    sdls_replay      a captured protected frame replayed with a fresh COP-1 sequence number
    sdls_flip        a protected frame with one bit flipped
"""
import time

from pqsat_testbed import paths  # noqa: F401
from pqsat_testbed.plugins import Attack
from ccsds_link import crc16


def _satlog(nodes, mark):
    sim = nodes.sats[nodes.serving]["sim"]
    return sim.log[mark:] if sim is not None else []


def _mark(nodes):
    sim = nodes.sats[nodes.serving]["sim"]
    return len(sim.log) if sim is not None else 0


def _inject_auth(nodes, adv, msg, sat_id):
    adv.vs = nodes.ue.vs                      # the sequence number the adversary observed
    ok = adv.send_auth(sat_id, msg)
    nodes.ue.vs = adv.vs                      # the genuine user resynchronises on the next CLCW
    return ok


class ReplayMsg1(Attack):
    name = "replay_msg1"
    description = "Replay a captured MSG1 inside the freshness window"

    def run(self, platform, nodes, adversary, captured_msg1=None, **_):
        sat_id = nodes.sats[nodes.serving]["scid"]
        mark = _mark(nodes)
        ok = _inject_auth(nodes, adversary, captured_msg1, sat_id)
        time.sleep(3)
        lines = _satlog(nodes, mark)
        return dict(name=self.name, accepted_by_link=ok,
                    rejected_by="satellite replay cache" if any("replayed MSG1" in l for l in lines) else None,
                    evidence=[l for l in lines if "replay" in l or "reject" in l])


class ForgedMsg3(Attack):
    name = "forged_msg3"
    description = "MSG3 with one bit flipped in the ground station's signature during a live handshake"

    def run(self, platform, nodes, adversary, genuine_msg3=None, **_):
        from ccsds_link import Terminal, ADDR_GS, TC_VC_GROUND
        from sim_link import SimModem
        sat_id = nodes.sats["sat1"]["scid"]
        adv_gs = Terminal(SimModem(nodes.sats["sat1"]["sim"], "ADV"), ADDR_GS, TC_VC_GROUND, scid=sat_id,
                          name="ADV-as-ground", show_hk=False, show_relay=False).start()
        forged = bytearray(genuine_msg3)
        forged[-100] ^= 0x01
        mark = _mark(nodes)
        adv_gs.vs = nodes.gs.vs
        ok = adv_gs.send_auth(sat_id, bytes(forged))
        nodes.gs.vs = adv_gs.vs
        adv_gs._run = False
        time.sleep(3)
        lines = _satlog(nodes, mark)
        return dict(name=self.name, accepted_by_link=ok,
                    rejected_by="ML-DSA half of the ground signature" if any("ground station signature rejected" in l
                                                                           for l in lines) else None,
                    evidence=[l for l in lines if "reject" in l])


class JunkMsg1(Attack):
    name = "junk_msg1"
    description = "MSG1 shaped message with a changed nonce during a live handshake"

    def run(self, platform, nodes, adversary, captured_msg1=None, **_):
        sat_id = nodes.sats[nodes.serving]["scid"]
        junk = bytearray(captured_msg1)
        junk[8 + 35 + 1088] ^= 0x01
        mark = _mark(nodes)
        ok = _inject_auth(nodes, adversary, bytes(junk), sat_id)
        time.sleep(3)
        lines = _satlog(nodes, mark)
        return dict(name=self.name, accepted_by_link=ok,
                    rejected_by="user signature" if any("user signature rejected" in l for l in lines) else None,
                    evidence=[l for l in lines if "reject" in l])


class StaleMsg1(Attack):
    name = "stale_msg1"
    description = "MSG1 with a timestamp older than the freshness window"

    def run(self, platform, nodes, adversary, **_):
        import pqsat_proto as P
        from handshake_runner import load_bundle, ID_GS
        from pqsat_roles import UserSession
        sat_id = nodes.sats[nodes.serving]["scid"]
        b_ue, b_sat = load_bundle("ue1"), load_bundle(nodes.serving)
        u = UserSession(b_ue, full_certs=False)
        u.cache[sat_id] = b_sat["cert"]
        u.clock = lambda: int(time.time()) - 2 * P.FRESHNESS_S
        old = u.start(sat_id, ID_GS)[0][1]
        mark = _mark(nodes)
        ok = _inject_auth(nodes, adversary, old, sat_id)
        time.sleep(3)
        lines = _satlog(nodes, mark)
        return dict(name=self.name, accepted_by_link=ok,
                    rejected_by="freshness window" if any("stale timestamp" in l for l in lines) else None,
                    evidence=[l for l in lines if "stale" in l])


class SdlsClear(Attack):
    name = "sdls_clear"
    description = "A clear frame on the user's channel while it is under SDLS"

    def run(self, platform, nodes, adversary, **_):
        mark = _mark(nodes)
        pkt = bytes([0x08, 0x00, 0xC0, 0x00, 0x00, 0x05, 0x00, 0x11, 0x00, 0x01, 0x41, 0x42])
        adversary.vs = nodes.ue.vs
        adversary.send_ad(pkt)
        nodes.ue.vs = adversary.vs
        time.sleep(3)
        lines = _satlog(nodes, mark)
        nodes.ue.init_cop()
        return dict(name=self.name, accepted_by_link=True,
                    rejected_by="SDLS (no security header)" if any("SDLS: TC on VC1 rejected" in l for l in lines)
                    else None, evidence=[l for l in lines if "SDLS" in l])


class SdlsReplay(Attack):
    name = "sdls_replay"
    description = "A captured protected frame replayed with a fresh COP-1 sequence number"

    def run(self, platform, nodes, adversary, captured_frame=None, **_):
        mark = _mark(nodes)
        f = bytearray(captured_frame)
        f[4] = nodes.ue.vs
        c = crc16(bytes(f[:-2]))
        f[-2:] = bytes([c >> 8, c & 0xFF])
        adversary.link.send(bytes(f))
        time.sleep(3)
        lines = _satlog(nodes, mark)
        nodes.ue.init_cop()
        return dict(name=self.name, accepted_by_link=True,
                    rejected_by="SDLS (MAC covers the header)" if any("SDLS: TC on VC1 rejected" in l for l in lines)
                    else None, evidence=[l for l in lines if "SDLS" in l])


class SdlsFlip(Attack):
    name = "sdls_flip"
    description = "A protected frame with one bit flipped"

    def run(self, platform, nodes, adversary, captured_frame=None, **_):
        mark = _mark(nodes)
        f = bytearray(captured_frame)
        f[4] = nodes.ue.vs
        f[30] ^= 0x01
        c = crc16(bytes(f[:-2]))
        f[-2:] = bytes([c >> 8, c & 0xFF])
        adversary.link.send(bytes(f))
        time.sleep(3)
        lines = _satlog(nodes, mark)
        nodes.ue.init_cop()
        return dict(name=self.name, accepted_by_link=True,
                    rejected_by="SDLS (MAC)" if any("SDLS: TC on VC1 rejected" in l for l in lines) else None,
                    evidence=[l for l in lines if "SDLS" in l])

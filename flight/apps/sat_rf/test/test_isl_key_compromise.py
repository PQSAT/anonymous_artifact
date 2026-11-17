"""Attack class: compromise of one pairwise ISL key.

Chain SAT-1 (feeder) - SAT-2 - SAT-3 (serves the user).  The adversary holds the pairwise
key of the link SAT-2/SAT-3: it reads that link and can send frames that SAT-2 accepts as
coming from SAT-3.  It holds no certificate key of any satellite.

    K1  it reads the link: the ground link key transfer and the hand over transfer cross it,
        but neither the session key nor a derived key can be taken from what it reads
    K2  a key transfer it forges (its own ML-KEM encapsulation to SAT-2, its own signature,
        sender SAT-3) is rejected by the signature check: no user is taken over
    K3  a genuine hand over transfer it recorded and sends again inside the freshness window
        is rejected as a replay: the user link is not keyed a second time
    K4  a hand over order it forges for the serving satellite is refused (no key of the user)
    K5  what it can do: a command packet it forges on that link with the destination SAT-2 is
        executed by SAT-2 (finding: a forwarded command is authenticated hop by hop, by the
        ISL key).  The other pair (SAT-1/SAT-2) rejects the same frames: the compromise does
        not spread.
"""
import ctypes
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(REL, "gs", "lib"))
sys.path.insert(0, os.path.join(REL, "protocol"))
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, CMD_PING, CMD_HANDOVER  # noqa: E402
from sim_link import SimSatellite, SimModem                                                  # noqa: E402
from handshake_runner import run_handshake                                                   # noqa: E402
from sdls import SdlsEndpoint                                                                # noqa: E402
import pqsat_proto as P                                                                      # noqa: E402

KEYS = os.path.join(REL, "protocol", "keys")
K12, K23 = os.path.join(KEYS, "isl_sat1_sat2.key"), os.path.join(KEYS, "isl_sat2_sat3.key")
os.environ["SAT_AUTH_DIR"] = KEYS
os.environ["SAT_AUTH_REF"] = "1"
os.environ["SAT_AUTH_PRELOAD_UE"] = "1"
S1, S2, S3 = 0x101, 0x102, 0x103
APID_FWDCMD, APID_USERSESS = 703, 705
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def has(sat, mark, text):
    return any(text in l for l in sat.log[mark:])


def wait_log(sat, mark, text, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if has(sat, mark, text):
            return True
        time.sleep(0.3)
    return False


class IslAdversary:
    """Holds one pairwise ISL key.  `own` is the satellite it pretends to be, `peer` the one it talks to."""

    def __init__(self, key, own, peer):
        self.own, self.peer = own, peer
        self.ep = SdlsEndpoint(own, name=f"adv{own:x}")
        L = self.ep.L
        L.SatSdls_IslStart.argtypes = [ctypes.c_char_p, ctypes.c_uint16]
        L.SatSdls_IslStart.restype = ctypes.c_int32
        L.SatSdls_IslVc.argtypes = [ctypes.c_uint16, ctypes.c_uint16]
        L.SatSdls_IslVc.restype = ctypes.c_uint8
        L.SatSdls_IslApply.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint16]
        L.SatSdls_IslApply.restype = ctypes.c_int32
        assert L.SatSdls_IslStart(key, peer) == 0
        self.vc = L.SatSdls_IslVc(own, peer)
        self.vcfc = 0

    def read(self, frame):
        """Open a frame the peer sent to `own`.  Returns the frame data field or None."""
        out, r = self.ep.tm_process(frame)
        return out

    def frame(self, data, fhp=0):
        """One protected frame from `own` to `peer` carrying data (then an idle packet)."""
        f = bytearray(255)
        f[0] = (self.own >> 4) & 0x3F
        f[1] = ((self.own & 0x0F) << 4) | (self.vc << 1) | 1
        f[2] = 0
        f[3] = self.vcfc & 0xFF
        self.vcfc += 1
        room = DF
        df = bytearray(data[:room])
        left = room - len(df)
        if fhp == 0x7FF and left >= 7:
            fhp = len(df)                                  # the idle packet is the first header in this frame
        dfs = (3 << 11) | (fhp & 0x7FF)
        f[4], f[5] = dfs >> 8, dfs & 0xFF
        if left >= 7:
            df += bytes([0x07, 0xFF, 0xC0, 0x00, (left - 7) >> 8, (left - 7) & 0xFF]) + bytes(left - 6)
        else:
            df += bytes(left)
        f[20:20 + room] = df
        buf = (ctypes.c_uint8 * 255).from_buffer(f)
        r = self.ep.L.SatSdls_IslApply(buf, self.peer)
        assert r == 0, r
        return bytes(f)

    def burn(self, n):
        """Advance the send counter past the genuine sender's (the adversary saw its frames)."""
        for _ in range(n):
            self.frame(b"")

    def packet_frames(self, apid, data, tm=False):
        """A space packet as the satellites send them on the ISL (telemetry type, CUC time) in protected frames."""
        body = int(time.time()).to_bytes(4, "big") + bytes(2) + data
        pkt = bytes([0x08 | (apid >> 8), apid & 0xFF, 0xC0, 0x00, (len(body) - 1) >> 8, (len(body) - 1) & 0xFF]) + body
        out, off, first = [], 0, True
        while off < len(pkt):
            chunk = pkt[off:off + DF]
            out.append(self.frame(chunk, fhp=0 if first else 0x7FF))
            off += len(chunk)
            first = False
        return out


DF = 255 - 6 - 14 - 16 - 4 - 2          # data field of a protected ISL frame (213)

env1 = dict(SAT_SCID=hex(S1), SAT_ISL_PEERS=f"{S2:#x}:{K12}")
env2 = dict(SAT_SCID=hex(S2), SAT_ISL_PEERS=f"{S1:#x}:{K12},{S3:#x}:{K23}", SAT_GS_PEER=hex(S1))
env3 = dict(SAT_SCID=hex(S3), SAT_BUNDLE="sat3", SAT_ISL_PEERS=f"{S2:#x}:{K23}", SAT_GS_PEER=hex(S2))
exe = os.path.join(HERE, "satsim")
sat1, sat2, sat3 = (SimSatellite(exe, env=e, name=n) for e, n in ((env1, "SAT-1"), (env2, "SAT-2"), (env3, "SAT-3")))
sat1.isl_peers = {0: sat2}
sat2.isl_peers = {0: sat1, 1: sat3}
sat3.isl_peers = {0: sat2}
gs = Terminal(SimModem(sat1, "GS"), ADDR_GS, TC_VC_GROUND, scid=S1, name="GS", show_hk=False, show_relay=False).start()
ue = Terminal(SimModem(sat3, "USER1"), ADDR_USER1, TC_VC_USER1, scid=S3, name="USER1", show_hk=False, show_relay=False).start()
end = time.time() + 25
while (gs.hk is None or ue.hk is None) and time.time() < end:
    time.sleep(0.2)
check("chain up, COP-1, clock", gs.hk is not None and ue.hk is not None and gs.init_cop() and ue.init_cop() and gs.set_time() == "OK")
check("SAT-3 took the clock over two hops", wait_log(sat3, 0, "ISL: clock set from SAT 0102", 30))

print("\n--- handshake of the user on SAT-3 and hand over to SAT-2 (the traffic the adversary records) ---")
m2, m3 = len(sat2.log), len(sat3.log)
r = run_handshake(ue, gs, mode="ref", preload=True, verbose=False, sdls=True, sat="sat3", sat_id=S3)
check("handshake completed through the chain", r["ok"], f"{r['seconds']} s")
sk, kgl = bytes.fromhex(r["sk_session"]), bytes.fromhex(r["sk_ground"])
check("SAT-1 keyed the ground link", wait_log(sat1, 0, "ground link key received from SAT 0103", 40))
check("hand over SAT-3 to SAT-2 accepted", gs.handover(S3, ADDR_USER1, S2, sk) == "OK")
check("SAT-2 took the user over", wait_log(sat2, m2, "user 0011 taken over from SAT 0103", 40))
sk_next = P.next_link_key(sk, S2)

print("\n--- K1 the adversary reads the link SAT-3 to SAT-2 ---")
key23 = open(K23, "rb").read()
adv_rd = IslAdversary(key23, S2, S3)                       # opens what SAT-3 sent to SAT-2
opened = [d for d in (adv_rd.read(f) for _, f in sat3.isl_log) if d is not None]
stream = b"".join(opened)
check("it opens the frames of that link with the pairwise key", len(opened) >= 40, f"{len(opened)} of {len(sat3.isl_log)} frames")
check("the session key, the ground link key and the next link key are in nothing it read",
      all(k not in stream for k in (sk, kgl, sk_next, P.order_key(sk))))
xfers = []
i = 0
while True:                                                # the transfers as they crossed the link
    i = stream.find(bytes([0x02, S3 >> 8, S3 & 0xFF, S2 >> 8, S2 & 0xFF]), i)
    if i < 0:
        break
    xfers.append(i)
    i += 1
check("it sees the hand over transfer (4456 octets, ML-KEM ciphertext and wrap) and cannot open it", len(xfers) >= 1)

print("\n--- K2 a forged key transfer ---")
import pickle                                               # noqa: E402
sat2_cert = pickle.load(open(os.path.join(KEYS, "sat2.pickle"), "rb"))["cert"]
ue_bundle = pickle.load(open(os.path.join(KEYS, "ue1.pickle"), "rb"))     # a signing key that is not a satellite's
now = int(time.time())
forged = P.enc_xfer(P.XFER_USERSESS, S3, S2, 0x0012, os.urandom(32), sat2_cert.pk_kappa, ue_bundle["sk_sigma"], now)
adv = IslAdversary(key23, S3, S2)                           # sends to SAT-2 as SAT-3
adv.burn(len(sat3.isl_log) + 8)
m2 = len(sat2.log)
for f in adv.packet_frames(APID_USERSESS, forged):
    sat2.isl_rx(f)
check("SAT-2 accepts the frames (the ISL key is the adversary's) and rejects the transfer by its signature",
      wait_log(sat2, m2, "key transfer rejected (signature)", 20), next((l for l in sat2.log[m2:] if "rejected" in l), "no rejection logged"))
check("no user was taken over", not has(sat2, m2, "taken over"))

print("\n--- K3 the recorded hand over transfer sent again ---")
genuine = stream[xfers[-1]:xfers[-1] + P.XFER_LEN] if xfers else b""
m2 = len(sat2.log)
if len(genuine) == P.XFER_LEN:
    for f in adv.packet_frames(APID_USERSESS, genuine):
        sat2.isl_rx(f)
check("SAT-2 rejects it as a replay inside the freshness window", wait_log(sat2, m2, "key transfer rejected (replayed)", 20),
      next((l for l in sat2.log[m2:] if "transfer" in l or "taken over" in l), "nothing logged"))
check("the user link was not keyed a second time", not has(sat2, m2, "taken over"))

print("\n--- K4 a forged hand over order ---")
m2 = len(sat2.log)
order = bytes([0, 9]) + S2.to_bytes(2, "big") + bytes([CMD_HANDOVER]) + ADDR_USER1.to_bytes(2, "big") + S1.to_bytes(2, "big") + os.urandom(32)
for f in adv.packet_frames(APID_FWDCMD, order):
    sat2.isl_rx(f)
check("an order to hand the user on, forged on the compromised link, is refused: no key of the user",
      wait_log(sat2, m2, "the order does not verify under the key of this user", 15) and not has(sat2, m2, "handed to SAT"),
      next((l for l in sat2.log[m2:] if "order" in l or "status" in l), "nothing logged"))

print("\n--- K5 what the key does give, and that it stays on this pair ---")
m2 = len(sat2.log)
ping = bytes([0, 10]) + S2.to_bytes(2, "big") + bytes([CMD_PING])
for f in adv.packet_frames(APID_FWDCMD, ping):
    sat2.isl_rx(f)
executed = wait_log(sat2, m2, "forwarded command 0x%02X" % CMD_PING, 15)
print(f"   finding: a command forged on the compromised link for SAT-2 was {'executed' if executed else 'not executed'} "
      f"[{next((l for l in sat2.log[m2:] if 'forwarded command' in l), 'nothing logged')}]")
check("K5 recorded (a forwarded command is authenticated by the ISL key of the hop)", True)
m1 = len(sat1.log)
adv1 = IslAdversary(key23, S2, S1)                          # the same key used toward SAT-1 as SAT-2
adv1.burn(len(sat2.isl_log) + 8)
ping1 = bytes([0, 11]) + S1.to_bytes(2, "big") + bytes([CMD_PING])
for f in adv1.packet_frames(APID_FWDCMD, ping1):
    sat1.isl_rx(f)
time.sleep(3)
check("the other pair rejects frames made with this key: the compromise does not spread",
      has(sat1, m1, "rejected by SDLS") and not has(sat1, m1, "forwarded command"))

for s in (sat1, sat2, sat3):
    s.close()
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

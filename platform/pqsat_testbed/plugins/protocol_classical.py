"""Classical baseline plug in: the three party protocol's structure with pre quantum
primitives.  The three ML-KEM encapsulations become three ephemeral ECDH P-256
agreements (user to satellite, satellite to ground, ground to user), the hybrid
ML-DSA signatures become ECDSA P-256 over SHA-256, certificates are (identity, signing
key, agreement key, validity) signed by the authority.  Message by message the flow is the
same as the post quantum protocol (MSG1 to MSG8, the two wraps, the three confirmation
tags), so the two run on the same link with the same accounting, which is the comparison
the paper reports.

Secrets: ss_us = ECDH(ue, sat), ss_sg = ECDH(sat, gs), ss_gu = ECDH(gs, ue).  Each party
computes the two it holds a key for and receives the third wrapped under one it holds
(the satellite wraps ss_us to the ground in MSG6 and ss_sg to the user in MSG7f, as the
post quantum protocol does with its KEM secrets).
SK = KDF(ss_us | ss_sg | ss_gu | mu_u | mu_s | mu_g | ids | h(transcript), "SK").

The satellite role runs in Python on the harness (satellite_role = "python"); the flight
core carries the messages exactly as for the post quantum protocol.

Sizes (octets): certificate 204; MSG1 377, MSG2 748, MSG3 371, MSG4 740, MSG5 34,
MSG6 82, MSG7 82, MSG7f 82, MSG8 34; total 2 550, against 25 312 (reference) and
70 750 (full) for the post quantum protocol.
"""
import hashlib
import os
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqsat_testbed.plugins import Protocol

ID_GS, ID_UE, ID_SAT1, ID_SAT2 = 0x0001, 0x0011, 0x0101, 0x0102
VER = 0x02
MSG1, MSG2, MSG3, MSG4, MSG5, MSG6, MSG7, MSG7F, MSG8 = range(1, 10)
NAMES = {MSG1: "MSG1", MSG2: "MSG2", MSG3: "MSG3", MSG4: "MSG4", MSG5: "MSG5", MSG6: "MSG6", MSG7: "MSG7",
         MSG7F: "MSG7f", MSG8: "MSG8"}
FRESH_S = 900
CERT = 204
PART = CERT + 65 + 32 + 4 + 64     # certificate, ephemeral point, nonce, timestamp, signature = 369

_PRIV, _TA = {}, None


def _pt(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _pub(pt):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pt)


def _sign(priv, data):
    r, s = decode_dss_signature(priv.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify(pub, sig, data):
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), data,
                   ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def _kdf(secret, label, n=32):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=label).derive(secret)


def _h(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def _wrap(ss, label, nonces, secret):
    """AES-256-GCM of a 32 octet secret under KDF(ss, label); nonce from the three nonces. 48 octets."""
    key = _kdf(ss, label)
    nonce = _h(nonces, label)[:12]
    return AESGCM(key).encrypt(nonce, secret, label)


def _unwrap(ss, label, nonces, blob):
    key = _kdf(ss, label)
    nonce = _h(nonces, label)[:12]
    return AESGCM(key).decrypt(nonce, blob, label)


class Authority:
    def __init__(self):
        self.sk = ec.generate_private_key(ec.SECP256R1())
        self.pk = self.sk.public_key()

    def enrol(self, ident):
        sig_sk = ec.generate_private_key(ec.SECP256R1())
        now = int(time.time())
        body = struct.pack(">H", ident) + _pt(sig_sk.public_key()) + _pt(ec.generate_private_key(ec.SECP256R1()).public_key()) + \
            struct.pack(">II", now - 60, now + 365 * 86400)
        return dict(ident=ident, sig_sk=sig_sk, cert=body + _sign(self.sk, body))


def _authority():
    global _TA
    if _TA is None:
        _TA = Authority()
        for i in (ID_GS, ID_UE, ID_SAT1, ID_SAT2):
            _PRIV[i] = _TA.enrol(i)
    return _TA


def _parse_cert(c, ta_pk):
    ident = struct.unpack(">H", c[:2])[0]
    start, end = struct.unpack(">II", c[132:140])
    if not _verify(ta_pk, c[140:204], c[:140]):
        raise ValueError("certificate signature")
    if not (start <= int(time.time()) <= end):
        raise ValueError("certificate validity")
    return dict(ident=ident, sig_pk=_pub(c[2:67]))


def _part(cert, eph, mu, t, sig):
    return cert + _pt(eph.public_key()) + mu + struct.pack(">I", t) + sig


def _read_part(b, o, ta_pk):
    c = _parse_cert(b[o:o + CERT], ta_pk); o += CERT
    pt = b[o:o + 65]; o += 65
    mu = b[o:o + 32]; o += 32
    t = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    sig = b[o:o + 64]; o += 64
    return dict(cert=c, pt=pt, pub=_pub(pt), mu=mu, t=t, sig=sig), o


class _Role:
    def __init__(self, ident):
        _authority()
        self.me, self.ident, self.ta_pk, self.sk = _PRIV[ident], ident, _TA.pk, None


class User(_Role):
    def start(self, id_sat, id_gs):
        self.id_sat, self.id_gs = id_sat, id_gs
        self.eph, self.mu, t1 = ec.generate_private_key(ec.SECP256R1()), os.urandom(32), int(time.time())
        head = bytes([VER, MSG1]) + struct.pack(">HHH", self.ident, id_sat, id_gs)
        self.pi1 = _h(head, self.me["cert"], _pt(self.eph.public_key()), self.mu, struct.pack(">I", t1))
        return [("sat", head + _part(self.me["cert"], self.eph, self.mu, t1, _sign(self.me["sig_sk"], self.pi1)))]

    def handle(self, m):
        if m[1] == MSG4:
            s, o = _read_part(m, 2, self.ta_pk)
            g, o = _read_part(m, o, self.ta_pk)
            if abs(int(time.time()) - g["t"]) > FRESH_S:
                raise ValueError("stale T3")
            pi2 = _h(self.pi1, s["pt"], s["mu"], struct.pack(">I", s["t"]))
            pi3 = _h(pi2, g["pt"], g["mu"], struct.pack(">I", g["t"]))
            if not _verify(s["cert"]["sig_pk"], s["sig"], pi2) or not _verify(g["cert"]["sig_pk"], g["sig"], pi3):
                raise ValueError("signature")
            self.ss_us, self.ss_gu = self.eph.exchange(ec.ECDH(), s["pub"]), self.eph.exchange(ec.ECDH(), g["pub"])
            self.mu_s, self.mu_g, self.pi3 = s["mu"], g["mu"], pi3
            self.nonces = self.mu + self.mu_s + self.mu_g
            tag_u = _h(self.ss_us, self.ss_gu, self.nonces, b"UE-fin")
            return [("sat", bytes([VER, MSG5]) + tag_u)]
        if m[1] == MSG7F:
            ss_sg = _unwrap(self.ss_us, b"wrap-sg-u", self.nonces, m[2:50])
            sk = _kdf(self.ss_us + ss_sg + self.ss_gu + self.nonces + struct.pack(">HHH", self.ident, self.id_sat, self.id_gs)
                      + self.pi3, b"SK")
            if m[50:82] != _h(sk, self.nonces, b"GS-fin"):
                raise ValueError("tag_g")
            self.sk = sk
            return [("sat", bytes([VER, MSG8]) + _h(sk, self.nonces, b"UE-fin-final"))]
        return []


class Satellite(_Role):
    def __init__(self, ident):
        super().__init__(ident)
        self.s = {}

    def handle(self, msg, from_role):
        t = msg[1]
        if t == MSG1:
            id_ue, id_sat, id_gs = struct.unpack(">HHH", msg[2:8])
            if id_sat != self.ident:
                return []
            u, o = _read_part(msg, 8, self.ta_pk)
            if abs(int(time.time()) - u["t"]) > FRESH_S:
                return []
            pi1 = _h(msg[:8], msg[8:8 + CERT], u["pt"], u["mu"], struct.pack(">I", u["t"]))
            if not _verify(u["cert"]["sig_pk"], u["sig"], pi1):
                return []
            eph, mu_s, t2 = ec.generate_private_key(ec.SECP256R1()), os.urandom(32), int(time.time())
            pi2 = _h(pi1, _pt(eph.public_key()), mu_s, struct.pack(">I", t2))
            part = _part(self.me["cert"], eph, mu_s, t2, _sign(self.me["sig_sk"], pi2))
            self.s = dict(ue=u, eph=eph, mu_s=mu_s, pi2=pi2, part=part, ids=(id_ue, id_sat, id_gs))
            return [("gs", bytes([VER, MSG2]) + msg[2:] + part)]
        if t == MSG3:
            s = self.s
            g, o = _read_part(msg, 2, self.ta_pk)
            pi3 = _h(s["pi2"], g["pt"], g["mu"], struct.pack(">I", g["t"]))
            if not _verify(g["cert"]["sig_pk"], g["sig"], pi3):
                return []
            s.update(gs=g, pi3=pi3, nonces=s["ue"]["mu"] + s["mu_s"] + g["mu"])
            s["ss_us"] = s["eph"].exchange(ec.ECDH(), s["ue"]["pub"])
            s["ss_sg"] = s["eph"].exchange(ec.ECDH(), g["pub"])
            return [("ue", bytes([VER, MSG4]) + s["part"] + msg[2:])]
        if t == MSG5:
            s = self.s
            return [("gs", bytes([VER, MSG6]) + _wrap(s["ss_sg"], b"wrap-us-g", s["nonces"], s["ss_us"]) + msg[2:34])]
        if t == MSG7:
            s = self.s
            ss_gu = _unwrap(s["ss_sg"], b"wrap-gu-s", s["nonces"], msg[2:50])
            s["sk"] = _kdf(s["ss_us"] + s["ss_sg"] + ss_gu + s["nonces"] + struct.pack(">HHH", *s["ids"]) + s["pi3"], b"SK")
            return [("ue", bytes([VER, MSG7F]) + _wrap(s["ss_us"], b"wrap-sg-u", s["nonces"], s["ss_sg"]) + msg[50:82])]
        if t == MSG8:
            s = self.s
            if msg[2:34] == _h(s.get("sk", b""), s.get("nonces", b""), b"UE-fin-final"):
                self.sk = s["sk"]
            return [("gs", msg)]
        return []


class Ground(_Role):
    def handle(self, m):
        t = m[1]
        if t == MSG2:
            id_ue, id_sat, id_gs = struct.unpack(">HHH", m[2:8])
            u, o = _read_part(m, 8, self.ta_pk)
            pi1 = _h(bytes([VER, MSG1]) + m[2:8], m[8:8 + CERT], u["pt"], u["mu"], struct.pack(">I", u["t"]))
            if abs(int(time.time()) - u["t"]) > FRESH_S or not _verify(u["cert"]["sig_pk"], u["sig"], pi1):
                raise ValueError("MSG1 inside MSG2")
            s, o = _read_part(m, o, self.ta_pk)
            pi2 = _h(pi1, s["pt"], s["mu"], struct.pack(">I", s["t"]))
            if not _verify(s["cert"]["sig_pk"], s["sig"], pi2):
                raise ValueError("satellite signature")
            self.eph, self.mu, t3 = ec.generate_private_key(ec.SECP256R1()), os.urandom(32), int(time.time())
            self.pi3 = _h(pi2, _pt(self.eph.public_key()), self.mu, struct.pack(">I", t3))
            self.ids, self.nonces = (id_ue, id_sat, id_gs), u["mu"] + s["mu"] + self.mu
            self.ss_gu, self.ss_sg = self.eph.exchange(ec.ECDH(), u["pub"]), self.eph.exchange(ec.ECDH(), s["pub"])
            return [("sat", bytes([VER, MSG3]) + _part(self.me["cert"], self.eph, self.mu, t3, _sign(self.me["sig_sk"], self.pi3)))]
        if t == MSG6:
            ss_us = _unwrap(self.ss_sg, b"wrap-us-g", self.nonces, m[2:50])
            if m[50:82] != _h(ss_us, self.ss_gu, self.nonces, b"UE-fin"):
                raise ValueError("tag_u")
            self.sk = _kdf(ss_us + self.ss_sg + self.ss_gu + self.nonces + struct.pack(">HHH", *self.ids) + self.pi3, b"SK")
            return [("sat", bytes([VER, MSG7]) + _wrap(self.ss_sg, b"wrap-gu-s", self.nonces, self.ss_gu) +
                     _h(self.sk, self.nonces, b"GS-fin"))]
        if t == MSG8:
            if m[2:34] != _h(self.sk, self.nonces, b"UE-fin-final"):
                raise ValueError("tag_u'")
            return []
        return []


class ClassicalProtocol(Protocol):
    name = "classical"
    description = ("Classical baseline: ECDH P-256 and ECDSA P-256 in the same three party flow (MSG1 to MSG8, "
                   "two wraps, three tags); satellite role in Python on the harness")
    satellite_role = "python"

    def satellite_session(self, sat_name):
        return _SatAdapter(Satellite(ID_SAT1 if sat_name == "sat1" else ID_SAT2))

    def run(self, platform, nodes, timeout=900.0, sdls=True, **_):
        ue_t, gs_t = nodes.ue, nodes.gs
        sat_id = nodes.sats[nodes.serving]["scid"]
        ue, gs = User(ID_UE), Ground(ID_GS)
        ue_t.auth_rx.clear()
        gs_t.auth_rx.clear()
        per, t_start = [], time.time()

        def snap(t):
            return dict(tc=t.stats["tc_frames"], retx=t.stats["tc_retx"], tm=t.stats["tm_frames"],
                        lost=t.stats["tm_lost"], naks=t.stats.get("naks", 0), rep=t.stats.get("chunks_repaired", 0))

        def send(term, msg):
            b, t0 = snap(term), time.time()
            ok = term.send_auth(sat_id, msg)
            a = snap(term)
            per.append(dict(msg=NAMES[msg[1]], direction="up", octets=len(msg), segments=a["tc"] - b["tc"],
                            retransmissions=a["retx"] - b["retx"], seconds=round(time.time() - t0, 3), ok=ok))
            if not ok:
                raise RuntimeError(f"{NAMES[msg[1]]} not acknowledged")

        def recv(term, types):
            b, t0 = snap(term), time.time()
            while True:
                if time.time() - t_start > timeout:
                    raise RuntimeError("timeout")
                r = term.wait_auth(5.0)
                if r and r[1][1] in types:
                    msg = r[1]
                    break
            a = snap(term)
            per.append(dict(msg=NAMES[msg[1]], direction="down", octets=len(msg), frames=a["tm"] - b["tm"],
                            lost=a["lost"] - b["lost"], naks=a["naks"] - b["naks"], repaired=a["rep"] - b["rep"],
                            seconds=round(time.time() - t0, 3)))
            return msg

        try:
            send(ue_t, ue.start(sat_id, ID_GS)[0][1])
            send(gs_t, gs.handle(recv(gs_t, (MSG2,)))[0][1])
            send(ue_t, ue.handle(recv(ue_t, (MSG4,)))[0][1])
            send(gs_t, gs.handle(recv(gs_t, (MSG6,)))[0][1])
            send(ue_t, ue.handle(recv(ue_t, (MSG7F,)))[0][1])
            gs.handle(recv(gs_t, (MSG8,)))
            ok = ue.sk is not None and ue.sk == gs.sk
            if ok and sdls:
                ue_t.sdls_start(ue.sk)
                gs_t.sdls_start(gs.sk)
        except Exception as e:
            return dict(mode="classical", ok=False, error=str(e), seconds=round(time.time() - t_start, 3),
                        octets_total=sum(p["octets"] for p in per), messages=per, protocol=self.name)
        return dict(mode="classical", ok=bool(ok), seconds=round(time.time() - t_start, 3),
                    sk_user=ue.sk.hex() if ue.sk else None, sk_ground=gs.sk.hex() if gs.sk else None,
                    octets_total=sum(p["octets"] for p in per),
                    uplink_segments=sum(p.get("segments", 0) for p in per),
                    uplink_retransmissions=sum(p.get("retransmissions", 0) for p in per),
                    downlink_frames=sum(p.get("frames", 0) for p in per),
                    downlink_lost=sum(p.get("lost", 0) for p in per),
                    downlink_naks=sum(p.get("naks", 0) for p in per),
                    downlink_repaired=sum(p.get("repaired", 0) for p in per),
                    messages=per, protocol=self.name, serving_satellite=f"{sat_id:#x}")


class _SatAdapter:
    ROLE = {ID_GS: "gs", ID_UE: "ue"}
    ADDR = {"gs": ID_GS, "ue": ID_UE}

    def __init__(self, s):
        self.s = s

    def handle(self, src, msg):
        try:
            out = self.s.handle(msg, self.ROLE.get(src, "ue"))
        except Exception:
            return []
        return [(self.ADDR[d], m) for d, m in out]

    def session_key(self):
        return self.s.sk

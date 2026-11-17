"""Protocol codec and cryptographic operations (PROTOCOL.md).

Every encoding here is the one in PROTOCOL.md.  The C codec on
the satellite reproduces these layouts octet for octet, and test_codec checks
that both sides agree.  All primitives come from libpqsat through pqsat.py.

Entities:  TA (offline), SAT, GS, UE.  Identities are 16 bit.
"""
import struct
import os
import time

import pqsat
from pqsat import ML_DSA_65 as DSA, ML_KEM_768 as KEM

VERSION = 0x03

# message types
MSG1, MSG2, MSG3, MSG4, MSG5, MSG6, MSG7, MSG7_FWD, MSG8, DEMAND = (
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x7F)
CRL = 0x0A                 # revocation list signed by the trusted authority
MSG8_FWD = 0x0B            # MSG8 as the satellite forwards it: tag_u' and the satellite's tag_s

# certificate roles: every node checks the role of a certificate before it uses it
ROLE_UE, ROLE_SAT, ROLE_GS = 0x01, 0x02, 0x03
ROLE_NAMES = {ROLE_UE: "user", ROLE_SAT: "satellite", ROLE_GS: "ground station"}
REVOKED_MAX = 64

# fixed sizes
ID_LEN, ROLE_LEN, NONCE_LEN, TS_LEN, HASH_LEN, TAG_LEN = 2, 1, 32, 4, 32, 32
CERT_BODY_LEN = ID_LEN + ROLE_LEN + DSA.pk_len + KEM.pk_len + HASH_LEN + 2 * TS_LEN  # 3179
CERT_SIG_LEN = KEM.ct_len + DSA.sig_len + TAG_LEN                        # 4429
CERT_BUNDLE_LEN = CERT_BODY_LEN + CERT_SIG_LEN                            # 7608
CERT_REF_LEN = ID_LEN + HASH_LEN                                          # 34
HSIG_LEN = DSA.sig_len + TAG_LEN                                          # 3341
WRAP_LEN = 64 + 16                                                        # 80: one session secret and one authentication secret
EPK_LEN, ECT_LEN = KEM.pk_len, KEM.ct_len                                # 1184, 1088

CERT_MODE_REF, CERT_MODE_FULL = 0x00, 0x01

LABEL_CERT_MAC = "cert-mac"
LABEL_HSIG_MAC = "HSig-MAC"
LABEL_SK = "SK"

APID_AUTH = 700
# Freshness window (seconds).  Must cover clock skew plus the worst case
# transfer time of the message path up to the point of check.  On the CCSDS
# LoRa link one full certificate message takes 100 to 160 s to cross, and a
# timestamp is checked after two such messages, so 60 s (a terrestrial figure)
# fails; 900 s covers full certificate mode at 10 percent frame loss with margin.
# Replay is bounded by the satellite's nonce cache, not by this window.  Override
# with PQSAT_FRESH_S for experiments.
FRESHNESS_S = int(os.environ.get("PQSAT_FRESH_S", "900"))


class ProtocolError(Exception):
    pass


# ---------------------------------------------------------------- primitives

def h(*parts):
    return pqsat.sha3_256(b"".join(parts))


def u16(x):
    return struct.pack(">H", x)


def u32(x):
    return struct.pack(">I", x)


def hybrid_sign(sk_sigma, ss, digest):
    """Σ = (σ, τ): ML-DSA over the digest, HMAC over the digest keyed from ss."""
    sigma = DSA.sign(digest, sk_sigma)
    tau = pqsat.hmac_sha3_256(pqsat.kdf(ss, LABEL_HSIG_MAC), digest)
    return sigma + tau


def hybrid_verify(pk_sigma, ss, digest, hsig, require_kem=True):
    """Both halves must verify.  With require_kem False only the ML-DSA half is
    checked, which is the deferred case the protocol allows when the keying
    secret has not yet arrived; the caller must complete the check later."""
    if len(hsig) != HSIG_LEN:
        return False
    sigma, tau = hsig[:DSA.sig_len], hsig[DSA.sig_len:]
    if not DSA.verify(sigma, digest, pk_sigma):
        return False
    if not require_kem:
        return True
    return tau == pqsat.hmac_sha3_256(pqsat.kdf(ss, LABEL_HSIG_MAC), digest)


def verify_kem_half(ss, digest, hsig):
    """Complete a deferred verification once ss is known."""
    tau = hsig[DSA.sig_len:]
    return tau == pqsat.hmac_sha3_256(pqsat.kdf(ss, LABEL_HSIG_MAC), digest)


# ---------------------------------------------------------------- certificates

class Certificate:
    """Body plus the trusted authority's hybrid signature, exactly as carried."""

    def __init__(self, ident, role, pk_sigma, pk_kappa, omega, not_before, not_after, c_cert, sigma_cert, tau_cert):
        self.ident, self.role, self.pk_sigma, self.pk_kappa, self.omega = ident, role, pk_sigma, pk_kappa, omega
        self.not_before, self.not_after = not_before, not_after
        self.c_cert, self.sigma_cert, self.tau_cert = c_cert, sigma_cert, tau_cert

    def body(self):
        return (u16(self.ident) + bytes([self.role]) + self.pk_sigma + self.pk_kappa + self.omega
                + u32(self.not_before) + u32(self.not_after))

    def digest(self):
        return h(self.body())

    def bundle(self):
        return self.body() + self.c_cert + self.sigma_cert + self.tau_cert

    def reference(self):
        return u16(self.ident) + self.digest()

    @classmethod
    def from_bundle(cls, b):
        if len(b) != CERT_BUNDLE_LEN:
            raise ProtocolError(f"certificate bundle is {len(b)} octets, expected {CERT_BUNDLE_LEN}")
        o = 0
        ident = struct.unpack(">H", b[o:o + 2])[0]; o += 2
        role = b[o]; o += 1
        pk_sigma = b[o:o + DSA.pk_len]; o += DSA.pk_len
        pk_kappa = b[o:o + KEM.pk_len]; o += KEM.pk_len
        omega = b[o:o + HASH_LEN]; o += HASH_LEN
        nb, na = struct.unpack(">II", b[o:o + 8]); o += 8
        c_cert = b[o:o + KEM.ct_len]; o += KEM.ct_len
        sigma = b[o:o + DSA.sig_len]; o += DSA.sig_len
        tau = b[o:o + TAG_LEN]
        return cls(ident, role, pk_sigma, pk_kappa, omega, nb, na, c_cert, sigma, tau)

    def verify(self, ta_pk_sigma, sk_kappa=None, now=None):
        """Verify the ML-DSA half against the authority.  The KEM half can be
        checked only by the subject itself (it needs sk_kappa to recover the
        MAC key), or by anyone given the published MAC key; peers therefore
        verify the ML-DSA half and the validity window, as the paper allows for
        certificate verification by third parties."""
        now = int(time.time()) if now is None else now
        if not (self.not_before <= now <= self.not_after):
            return False
        if not DSA.verify(self.sigma_cert, self.digest(), ta_pk_sigma):
            return False
        if sk_kappa is not None:
            ss = KEM.decaps(self.c_cert, sk_kappa)
            if self.tau_cert != pqsat.hmac_sha3_256(pqsat.kdf(ss, LABEL_CERT_MAC), self.digest()):
                return False
        return True


def encode_cert_field(cert, full):
    return bytes([CERT_MODE_FULL]) + cert.bundle() if full else bytes([CERT_MODE_REF]) + cert.reference()


def decode_cert_field(b, o):
    """Return (mode, payload, new offset)."""
    mode = b[o]; o += 1
    if mode == CERT_MODE_FULL:
        return mode, b[o:o + CERT_BUNDLE_LEN], o + CERT_BUNDLE_LEN
    if mode == CERT_MODE_REF:
        return mode, b[o:o + CERT_REF_LEN], o + CERT_REF_LEN
    raise ProtocolError(f"bad certificate mode {mode}")


# ---------------------------------------------------------------- the authority

class TrustedAuthority:
    """Phase 1.  Holds the long term keys and issues certificates (Phases 2 to 4)."""

    def __init__(self):
        self.pk_sigma, self.sk_sigma = DSA.keypair()
        self.pk_kappa, self.sk_kappa = KEM.keypair()
        self.master_key = pqsat.sha3_256(self.sk_sigma[:64] + b"K_TA")  # K_TA, 256 bit

    def enrol(self, ident, role, validity_days=365, now=None):
        """Generate the entity's key pairs and issue its hybrid signed certificate for the
        given role (ROLE_UE, ROLE_SAT or ROLE_GS).  Returns the bundle the entity's secure
        element holds."""
        if role not in ROLE_NAMES:
            raise ProtocolError(f"unknown role {role}")
        now = int(time.time()) if now is None else now
        pk_sigma, sk_sigma = DSA.keypair()
        pk_kappa, sk_kappa = KEM.keypair()
        alpha = h(u16(ident), self.master_key)
        omega = h(alpha, bytes([role]), pk_sigma, pk_kappa)
        cert = Certificate(ident, role, pk_sigma, pk_kappa, omega, now, now + validity_days * 86400, b"", b"", b"")
        c_cert, ss_cert = KEM.encaps(pk_kappa)
        k_cert = pqsat.kdf(ss_cert, LABEL_CERT_MAC)
        cert.c_cert = c_cert
        cert.sigma_cert = DSA.sign(cert.digest(), self.sk_sigma)
        cert.tau_cert = pqsat.hmac_sha3_256(k_cert, cert.digest())
        return dict(ident=ident, role=role, sk_sigma=sk_sigma, sk_kappa=sk_kappa, alpha=alpha, omega=omega,
                    cert=cert, ta_pk_sigma=self.pk_sigma, ta_pk_kappa=self.pk_kappa)

    def issue_crl(self, idents, issued=None):
        """Signed revocation list for the given identities (see enc_crl)."""
        return enc_crl(self.sk_sigma, idents, issued)


# ---------------------------------------------------------------- revocation

def enc_crl(ta_sk_sigma, idents, issued=None):
    """Revocation list message: issued 4 | count 2 | identities 2 each | ML-DSA-65 signature
    of the authority over the hash of those fields.  Any node holding the authority's
    verification key can check it, so it may travel over any link."""
    issued = int(time.time()) if issued is None else issued
    idents = sorted(set(idents))
    if len(idents) > REVOKED_MAX:
        raise ProtocolError("too many revoked identities for one list")
    body = u32(issued) + u16(len(idents)) + b"".join(u16(i) for i in idents)
    return header(CRL) + body + DSA.sign(h(body), ta_sk_sigma)


def dec_crl(b, ta_pk_sigma):
    """Return (issued, set of identities).  Raises ProtocolError unless the signature verifies."""
    o = check_header(b, CRL)
    if len(b) < o + 6 + DSA.sig_len:
        raise ProtocolError("revocation list too short")
    issued, n = struct.unpack(">IH", b[o:o + 6])
    body_len = 6 + 2 * n
    if n > REVOKED_MAX or len(b) != o + body_len + DSA.sig_len:
        raise ProtocolError("revocation list malformed")
    body = b[o:o + body_len]
    if not DSA.verify(b[o + body_len:], h(body), ta_pk_sigma):
        raise ProtocolError("revocation list signature rejected")
    return issued, set(struct.unpack(">%dH" % n, body[6:]))


# ---------------------------------------------------------------- messages

def header(mtype):
    return bytes([VERSION, mtype])


def check_header(b, mtype):
    if len(b) < 2 or b[0] != VERSION:
        raise ProtocolError("bad version")
    if b[1] != mtype:
        raise ProtocolError(f"expected message type {mtype:#x}, got {b[1]:#x}")
    return 2


# Two sets of secrets, and SK takes both.
#   Authentication secrets ss_us, ss_sg, ss_gu: encapsulated to long term ML-KEM keys
#   (c_us, c_sg, c_gu).  Only the holder of the receiver's long term key recovers one, so
#   each authenticates its receiver without any signature.  They key the KEM-MAC halves of
#   the hybrid signatures and enter SK, the wrap keys and tag_u.
#   Session secrets k_su, k_gs, k_gu: encapsulated to the ephemeral keys epk_u and epk_s
#   (e_su, e_gs, e_gu), erased with the ephemeral secret keys once SK exists (forward secrecy).
# SK is secret, and all three parties agree on it, if EITHER ML-DSA or ML-KEM is unbroken
# (Tamarin: formal/pqsat_handshake.spthy).

def transcript1(id_ue, id_sat, id_gs, omega_ue, h_c_us, h_epk_u, mu_u, t1):
    return u16(id_ue) + u16(id_sat) + u16(id_gs) + omega_ue + h_c_us + h_epk_u + mu_u + u32(t1)


def transcript2(pi1, id_sat, omega_sat, h_c_sg, h_epk_s, h_e_su, mu_s, t2):
    return pi1 + u16(id_sat) + omega_sat + h_c_sg + h_epk_s + h_e_su + mu_s + u32(t2)


def transcript3(pi2, id_gs, omega_gs, h_c_gu, h_e_gs, h_e_gu, mu_g, t3):
    return pi2 + u16(id_gs) + omega_gs + h_c_gu + h_e_gs + h_e_gu + mu_g + u32(t3)


def enc_msg1(id_ue, id_sat, id_gs, cert_field, c_us, epk_u, mu_u, t1, hsig_u):
    return (header(MSG1) + u16(id_ue) + u16(id_sat) + u16(id_gs) + cert_field + c_us + epk_u + mu_u + u32(t1)
            + hsig_u)


def dec_msg1(b):
    o = check_header(b, MSG1)
    id_ue, id_sat, id_gs = struct.unpack(">HHH", b[o:o + 6]); o += 6
    mode, cert, o = decode_cert_field(b, o)
    c_us = b[o:o + KEM.ct_len]; o += KEM.ct_len
    epk_u = b[o:o + EPK_LEN]; o += EPK_LEN
    mu_u = b[o:o + NONCE_LEN]; o += NONCE_LEN
    t1 = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    hsig = b[o:o + HSIG_LEN]; o += HSIG_LEN
    if o != len(b):
        raise ProtocolError("MSG1 length mismatch")
    return dict(id_ue=id_ue, id_sat=id_sat, id_gs=id_gs, cert_mode=mode, cert=cert, c_us=c_us, epk_u=epk_u,
                mu_u=mu_u, t1=t1, hsig_u=hsig)


def enc_msg2(ue_cert_field, h_c_us, epk_u, mu_u, t1, hsig_u, sat_cert_field, c_sg, epk_s, e_su, mu_s, t2, hsig_s):
    return (header(MSG2) + ue_cert_field + h_c_us + epk_u + mu_u + u32(t1) + hsig_u
            + sat_cert_field + c_sg + epk_s + e_su + mu_s + u32(t2) + hsig_s)


def dec_msg2(b):
    o = check_header(b, MSG2)
    umode, ucert, o = decode_cert_field(b, o)
    h_c_us = b[o:o + HASH_LEN]; o += HASH_LEN
    epk_u = b[o:o + EPK_LEN]; o += EPK_LEN
    mu_u = b[o:o + NONCE_LEN]; o += NONCE_LEN
    t1 = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    hsig_u = b[o:o + HSIG_LEN]; o += HSIG_LEN
    smode, scert, o = decode_cert_field(b, o)
    c_sg = b[o:o + KEM.ct_len]; o += KEM.ct_len
    epk_s = b[o:o + EPK_LEN]; o += EPK_LEN
    e_su = b[o:o + ECT_LEN]; o += ECT_LEN
    mu_s = b[o:o + NONCE_LEN]; o += NONCE_LEN
    t2 = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    hsig_s = b[o:o + HSIG_LEN]; o += HSIG_LEN
    if o != len(b):
        raise ProtocolError("MSG2 length mismatch")
    return dict(ue_cert_mode=umode, ue_cert=ucert, h_c_us=h_c_us, epk_u=epk_u, mu_u=mu_u, t1=t1, hsig_u=hsig_u,
                sat_cert_mode=smode, sat_cert=scert, c_sg=c_sg, epk_s=epk_s, e_su=e_su, mu_s=mu_s, t2=t2,
                hsig_s=hsig_s)


def enc_msg3(cert_field, c_gu, e_gs, e_gu, mu_g, t3, hsig_g):
    return header(MSG3) + cert_field + c_gu + e_gs + e_gu + mu_g + u32(t3) + hsig_g


def dec_msg3(b):
    o = check_header(b, MSG3)
    mode, cert, o = decode_cert_field(b, o)
    c_gu = b[o:o + KEM.ct_len]; o += KEM.ct_len
    e_gs = b[o:o + ECT_LEN]; o += ECT_LEN
    e_gu = b[o:o + ECT_LEN]; o += ECT_LEN
    mu_g = b[o:o + NONCE_LEN]; o += NONCE_LEN
    t3 = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    hsig_g = b[o:o + HSIG_LEN]; o += HSIG_LEN
    if o != len(b):
        raise ProtocolError("MSG3 length mismatch")
    return dict(cert_mode=mode, cert=cert, c_gu=c_gu, e_gs=e_gs, e_gu=e_gu, mu_g=mu_g, t3=t3, hsig_g=hsig_g)


def enc_msg4(sat_cert_field, h_c_sg, h_epk_s, e_su, mu_s, t2, hsig_s, gs_cert_field, c_gu, h_e_gs, e_gu, mu_g, t3,
             hsig_g):
    """Everything the user needs to rebuild the transcripts and recover its two session
    secrets: the satellite's contribution with e_su in full, the ground station's with
    e_gu in full.  epk_s and e_gs concern only the other two, so the user gets their hashes."""
    return (header(MSG4) + sat_cert_field + h_c_sg + h_epk_s + e_su + mu_s + u32(t2) + hsig_s
            + gs_cert_field + c_gu + h_e_gs + e_gu + mu_g + u32(t3) + hsig_g)


def dec_msg4(b):
    o = check_header(b, MSG4)
    smode, scert, o = decode_cert_field(b, o)
    h_c_sg = b[o:o + HASH_LEN]; o += HASH_LEN
    h_epk_s = b[o:o + HASH_LEN]; o += HASH_LEN
    e_su = b[o:o + ECT_LEN]; o += ECT_LEN
    mu_s = b[o:o + NONCE_LEN]; o += NONCE_LEN
    t2 = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    hsig_s = b[o:o + HSIG_LEN]; o += HSIG_LEN
    gmode, gcert, o = decode_cert_field(b, o)
    c_gu = b[o:o + KEM.ct_len]; o += KEM.ct_len
    h_e_gs = b[o:o + HASH_LEN]; o += HASH_LEN
    e_gu = b[o:o + ECT_LEN]; o += ECT_LEN
    mu_g = b[o:o + NONCE_LEN]; o += NONCE_LEN
    t3 = struct.unpack(">I", b[o:o + 4])[0]; o += 4
    hsig_g = b[o:o + HSIG_LEN]; o += HSIG_LEN
    if o != len(b):
        raise ProtocolError("MSG4 length mismatch")
    return dict(sat_cert_mode=smode, sat_cert=scert, h_c_sg=h_c_sg, h_epk_s=h_epk_s, e_su=e_su, mu_s=mu_s, t2=t2,
                hsig_s=hsig_s, gs_cert_mode=gmode, gs_cert=gcert, c_gu=c_gu, h_e_gs=h_e_gs, e_gu=e_gu, mu_g=mu_g,
                t3=t3, hsig_g=hsig_g)


def enc_msg5(tag_u):
    return header(MSG5) + tag_u


def dec_msg5(b):
    o = check_header(b, MSG5)
    if len(b) != o + TAG_LEN:
        raise ProtocolError("MSG5 length mismatch")
    return dict(tag_u=b[o:])


def enc_msg6(c_su_g, tag_u):
    return header(MSG6) + c_su_g + tag_u


def dec_msg6(b):
    o = check_header(b, MSG6)
    if len(b) != o + WRAP_LEN + TAG_LEN:
        raise ProtocolError("MSG6 length mismatch")
    return dict(c_su_g=b[o:o + WRAP_LEN], tag_u=b[o + WRAP_LEN:])


def enc_msg7(c_gs_u, c_gu_s, tag_g):
    return header(MSG7) + c_gs_u + c_gu_s + tag_g


def dec_msg7(b):
    o = check_header(b, MSG7)
    if len(b) != o + 2 * WRAP_LEN + TAG_LEN:
        raise ProtocolError("MSG7 length mismatch")
    return dict(c_gs_u=b[o:o + WRAP_LEN], c_gu_s=b[o + WRAP_LEN:o + 2 * WRAP_LEN], tag_g=b[o + 2 * WRAP_LEN:])


def enc_msg7_fwd(c_gs_u, tag_g, tag_s):
    return header(MSG7_FWD) + c_gs_u + tag_g + tag_s


def dec_msg7_fwd(b):
    o = check_header(b, MSG7_FWD)
    if len(b) != o + WRAP_LEN + 2 * TAG_LEN:
        raise ProtocolError("MSG7 forward length mismatch")
    return dict(c_gs_u=b[o:o + WRAP_LEN], tag_g=b[o + WRAP_LEN:o + WRAP_LEN + TAG_LEN],
                tag_s=b[o + WRAP_LEN + TAG_LEN:])


def enc_msg8(tag_u2):
    return header(MSG8) + tag_u2


def dec_msg8(b):
    o = check_header(b, MSG8)
    if len(b) != o + TAG_LEN:
        raise ProtocolError("MSG8 length mismatch")
    return dict(tag_u2=b[o:])


def enc_msg8_fwd(tag_u2, tag_s):
    """MSG8 as the satellite forwards it to the ground station, with its own confirmation."""
    return header(MSG8_FWD) + tag_u2 + tag_s


def dec_msg8_fwd(b):
    o = check_header(b, MSG8_FWD)
    if len(b) != o + 2 * TAG_LEN:
        raise ProtocolError("MSG8 forward length mismatch")
    return dict(tag_u2=b[o:o + TAG_LEN], tag_s=b[o + TAG_LEN:])


def enc_demand(status=0x01):
    return header(DEMAND) + bytes([status])


# ---------------------------------------------------------------- key material

def wrap_nonce(mu_u, mu_s, mu_g, label):
    return h(mu_u, mu_s, mu_g, label.encode())[:12]


def wrap(key_ss, mu_u, mu_s, mu_g, label, secret):
    return pqsat.aes256gcm_encrypt(key_ss, wrap_nonce(mu_u, mu_s, mu_g, label), secret)


def unwrap(key_ss, mu_u, mu_s, mu_g, label, blob):
    return pqsat.aes256gcm_decrypt(key_ss, wrap_nonce(mu_u, mu_s, mu_g, label), blob)


# wrap labels (nonce separation); each wrap carries one session secret and one authentication secret
W_SU_G, W_GS_U, W_GU_S = "wrap-su-g", "wrap-gs-u", "wrap-gu-s"
LABEL_W_SG, LABEL_W_GU = "wrap-sg", "wrap-gu"


def wrap_key_sg(k_gs, ss_sg):
    """W_sg, shared by the satellite and the ground station."""
    return pqsat.kdf(k_gs + ss_sg, LABEL_W_SG)


def wrap_key_gu(k_gu, ss_gu):
    """W_gu, shared by the ground station and the user."""
    return pqsat.kdf(k_gu + ss_gu, LABEL_W_GU)


def session_key(k_su, k_gs, k_gu, ss_us, ss_sg, ss_gu, mu_u, mu_s, mu_g, id_ue, id_sat, id_gs, pi3):
    """SK takes the three ephemeral session secrets (forward secrecy) and the three
    authentication secrets (authentication that does not depend on ML-DSA)."""
    return pqsat.kdf(k_su + k_gs + k_gu + ss_us + ss_sg + ss_gu + mu_u + mu_s + mu_g
                     + u16(id_ue) + u16(id_sat) + u16(id_gs) + pi3, LABEL_SK)


def tag_u(k_su, k_gu, ss_us, ss_gu, mu_u, mu_s, mu_g):
    """Proves to the ground station that the user holds ss_gu (its long term ML-KEM key)
    and agrees with the satellite on ss_us (so the satellite holds its own)."""
    return h(k_su, k_gu, ss_us, ss_gu, mu_u, mu_s, mu_g, b"UE-fin")


def tag_g(sk, mu_u, mu_s, mu_g):
    return h(sk, mu_u, mu_s, mu_g, b"GS-fin")


def tag_s(sk, mu_u, mu_s, mu_g):
    """The satellite's confirmation of SK, to the user in MSG7f and to the ground with MSG8."""
    return h(sk, mu_u, mu_s, mu_g, b"SAT-fin")


def tag_u_final(sk, mu_u, mu_s, mu_g):
    return h(sk, mu_u, mu_s, mu_g, b"UE-fin-final")


# keys derived from SK for the constellation phase: SK itself never leaves the serving satellite
def ground_link_key(sk):
    return pqsat.kdf(sk, "ground-link")


def order_key(sk):
    return pqsat.kdf(sk, "order")


def next_link_key(sk, id_next):
    return pqsat.kdf(sk + u16(id_next), "next-link")


def order_mac(k_ord, id_user, id_serving, id_target):
    """MAC of a hand over order, under the order key of the user it names."""
    return pqsat.hmac_sha3_256(k_ord, b"HANDOVER" + u16(id_user) + u16(id_serving) + u16(id_target))


# End to end key transfer between satellites (GLINK to the feeder, USERSESS to the next serving
# satellite):  label 1 | src 2 | dst 2 | user 2 | time 4 | c 1088 | AES-256-GCM(KDF(ss,"xfer"), key) 48
# | ML-DSA-65 signature 3309.  The header is the associated data of the wrap and the signature
# covers header, c and wrap.  Same layout as Auth_XferBuild in sat_auth.c.
XFER_GLINK, XFER_USERSESS = 0x01, 0x02
XFER_HDR = 11
XFER_LEN = XFER_HDR + KEM.ct_len + 32 + 16 + DSA.sig_len      # 4456


def enc_xfer(label, src, dst, user, key, dst_pk_kappa, src_sk_sigma, now=None):
    hdr = bytes([label]) + u16(src) + u16(dst) + u16(user) + u32(int(time.time()) if now is None else now)
    c, ss = KEM.encaps(dst_pk_kappa)
    w = pqsat.aes256gcm_encrypt(pqsat.kdf(ss, "xfer"), h(c)[:12], key, hdr)
    body = hdr + c + w
    return body + DSA.sign(h(body), src_sk_sigma)


def dec_xfer(b, label, dst, dst_sk_kappa, src_pk_sigma_of, now=None, window=FRESHNESS_S):
    """Open a transfer addressed to dst.  src_pk_sigma_of(ident) returns the ML-DSA key of a
    satellite certificate or None.  Returns (src, user, key)."""
    if len(b) != XFER_LEN or b[0] != label or struct.unpack(">H", b[3:5])[0] != dst:
        raise ProtocolError("transfer malformed or not for this satellite")
    src, user = struct.unpack(">H", b[1:3])[0], struct.unpack(">H", b[5:7])[0]
    pk = src_pk_sigma_of(src)
    if pk is None:
        raise ProtocolError("transfer from an unknown satellite")
    body, sig = b[:XFER_LEN - DSA.sig_len], b[XFER_LEN - DSA.sig_len:]
    if not DSA.verify(sig, h(body), pk):
        raise ProtocolError("transfer signature rejected")
    if not fresh(struct.unpack(">I", b[7:11])[0], now, window):
        raise ProtocolError("transfer stale")
    c, w = b[XFER_HDR:XFER_HDR + KEM.ct_len], body[XFER_HDR + KEM.ct_len:]
    key = pqsat.aes256gcm_decrypt(pqsat.kdf(KEM.decaps(c, dst_sk_kappa), "xfer"), h(c)[:12], w, b[:XFER_HDR])
    if key is None:
        raise ProtocolError("transfer wrap rejected")
    return src, user, key


def fresh(ts, now=None, window=FRESHNESS_S):
    now = int(time.time()) if now is None else now
    return abs(now - ts) <= window

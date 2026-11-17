"""Phase 5 state machines for the three roles, as pure message handlers.

Each role takes a message as bytes and returns zero or more (destination, bytes)
pairs to send.  No transport inside, so the same code runs in process for unit
tests, over the emulated link, and over the real radio.  The satellite logic is
reimplemented in C for the flight software and checked against this.

Destinations: "sat", "gs", "ue".
Protocol: PROTOCOL.md.
"""
import secrets
import time

import pqsat_proto as P
from pqsat import ML_KEM_768 as KEM


class HandshakeFailed(Exception):
    pass


def _now():
    return int(time.time())


class _Role:
    def __init__(self, bundle, full_certs=True, clock=_now):
        self.ident = bundle["ident"]
        self.role = bundle["cert"].role
        self.sk_sigma, self.sk_kappa = bundle["sk_sigma"], bundle["sk_kappa"]
        self.omega, self.cert = bundle["omega"], bundle["cert"]
        self.ta_pk = bundle["ta_pk_sigma"]
        self.full_certs = full_certs
        self.clock = clock
        self.cache = {}          # ident -> verified Certificate
        self.installed = set()   # identities whose certificate was provisioned at enrollment
        self.pin_installed = True   # certificate policy: an installed certificate is never replaced in band
        self.revoked = set()     # identities on the installed revocation list
        self.crl_issued = 0
        self.sk = None
        self.state = "idle"
        self.timing = {}         # op -> accumulated seconds
        self.events = []

    def _t(self, name, fn, *a):
        t0 = time.perf_counter()
        r = fn(*a)
        self.timing[name] = self.timing.get(name, 0.0) + (time.perf_counter() - t0)
        return r

    def note(self, *e):
        self.events.append(e)

    def cert_field(self):
        return P.encode_cert_field(self.cert, self.full_certs)

    def install_cert(self, cert):
        """Provision the certificate of a peer (enrollment or reprovisioning by the authority).
        This is the trusted binding of that identity: a certificate received in band is
        accepted only if it is the same one and never takes its place."""
        self.cache[cert.ident] = cert
        self.installed.add(cert.ident)

    def install_crl(self, b):
        """Install a revocation list message after verifying the authority's signature.
        An older list than the one held is refused.  Returns the number of revoked identities."""
        issued, idents = P.dec_crl(b, self.ta_pk)
        if issued <= self.crl_issued:
            raise HandshakeFailed("revocation list not newer than the one held")
        self.crl_issued, self.revoked = issued, idents
        for i in idents:
            self.cache.pop(i, None)
            self.installed.discard(i)
        return len(idents)

    def _not_revoked(self, ident):
        if ident in self.revoked:
            raise HandshakeFailed("identity is on the revocation list")

    def resolve_cert(self, mode, payload, expect_ident, expect_role):
        if expect_ident is not None:
            self._not_revoked(expect_ident)
        if mode == P.CERT_MODE_FULL:
            c = P.Certificate.from_bundle(payload)
            if not self._t("cert_verify", c.verify, self.ta_pk, None, self.clock()):
                raise HandshakeFailed("certificate rejected")
            held = self.cache.get(c.ident)
            if self.pin_installed and c.ident in self.installed and held is not None:
                if held.digest() != c.digest():
                    raise HandshakeFailed("certificate received in band differs from the installed one")
                c = held
            else:
                self.cache[c.ident] = c
        else:
            ident = int.from_bytes(payload[:2], "big")
            c = self.cache.get(ident)
            if c is None or c.digest() != payload[2:]:
                raise HandshakeFailed(("unknown certificate", ident))
        if c.ident != expect_ident:
            raise HandshakeFailed("certificate identity mismatch")
        self._role_ok(c, expect_role)
        return c

    @staticmethod
    def _role_ok(c, expect_role):
        if c.role != expect_role:
            raise HandshakeFailed(f"certificate role is {P.ROLE_NAMES.get(c.role, c.role)}, "
                                  f"expected {P.ROLE_NAMES[expect_role]}")

    def _erase(self, *names):
        """Forget ephemeral secret keys and session secrets once SK is derived."""
        for n in names:
            if hasattr(self, n):
                setattr(self, n, None)
        self.note("erased", names)

    def _fresh(self, ts):
        if not P.fresh(ts, self.clock()):
            raise HandshakeFailed("stale timestamp")

    def _verify(self, name, pk, ss, digest, hsig, require_kem=True):
        if not self._t("hybrid_verify", P.hybrid_verify, pk, ss, digest, hsig, require_kem):
            raise HandshakeFailed(f"{name} signature rejected")


# ------------------------------------------------------------------ user

class UserSession(_Role):
    def start(self, id_sat, id_gs):
        self.id_sat, self.id_gs = id_sat, id_gs
        sat_cert = self.cache.get(id_sat)
        if sat_cert is None:
            raise HandshakeFailed("user holds no certificate for the satellite")
        self._role_ok(sat_cert, P.ROLE_SAT)
        self.mu_u = secrets.token_bytes(P.NONCE_LEN)
        self.t1 = self.clock()
        self.c_us, self.ss_us = self._t("kem_encaps", KEM.encaps, sat_cert.pk_kappa)
        # ephemeral key pair of this handshake: the session secrets k_su and k_gu come back under it
        self.epk_u, self.esk_u = self._t("kem_keygen", KEM.keypair)
        self.pi1 = P.transcript1(self.ident, id_sat, id_gs, self.omega, P.h(self.c_us), P.h(self.epk_u),
                                 self.mu_u, self.t1)
        hsig = self._t("hybrid_sign", P.hybrid_sign, self.sk_sigma, self.ss_us, P.h(self.pi1))
        msg1 = P.enc_msg1(self.ident, id_sat, id_gs, self.cert_field(), self.c_us, self.epk_u, self.mu_u,
                          self.t1, hsig)
        self.state = "sent1"
        return [("sat", msg1)]

    def handle(self, b):
        t = b[1]
        if t == P.DEMAND and self.state == "sent1":
            self.note("demand", "resending with full certificate")
            self.full_certs = True
            return self.start(self.id_sat, self.id_gs)
        if t == P.MSG4 and self.state == "sent1":
            return self._on_msg4(b)
        if t == P.MSG7_FWD and self.state == "sent5":
            return self._on_msg7(b)
        raise HandshakeFailed(f"user: unexpected message {t:#x} in state {self.state}")

    def _on_msg4(self, b):
        d = P.dec_msg4(b)
        # T2 is not checked here: Pi2 is signed over mu_u, this user's own fresh nonce, so a
        # replayed satellite contribution fails on the nonce whatever T2 says, and T2 reaches
        # the user over three message transfers.  Freshness checks are kept where the
        # verifier has not yet contributed a nonce (satellite on T1, ground on T1 and T2).
        self._fresh(d["t3"])
        try:
            sat_cert = self.resolve_cert(d["sat_cert_mode"], d["sat_cert"], self.id_sat, P.ROLE_SAT)
            gs_cert = self.resolve_cert(d["gs_cert_mode"], d["gs_cert"], self.id_gs, P.ROLE_GS)
        except HandshakeFailed as e:
            if isinstance(e.args[0], tuple) and e.args[0][0] == "unknown certificate":
                self.note("demand", "missing a certificate, asking the satellite for full mode")
                return [("sat", P.enc_demand())]
            raise

        # rebuild the transcripts the two peers signed
        self.mu_s, self.mu_g = d["mu_s"], d["mu_g"]
        pi2 = P.transcript2(self.pi1, self.id_sat, sat_cert.omega, d["h_c_sg"], d["h_epk_s"], P.h(d["e_su"]),
                            d["mu_s"], d["t2"])
        self.pi3 = P.transcript3(pi2, self.id_gs, gs_cert.omega, P.h(d["c_gu"]), d["h_e_gs"], P.h(d["e_gu"]),
                                 d["mu_g"], d["t3"])

        # satellite: ML-DSA half now, KEM half deferred until ss_sg arrives in MSG7
        self._verify("satellite", sat_cert.pk_sigma, None, P.h(pi2), d["hsig_s"], require_kem=False)
        self.deferred_s = (P.h(pi2), d["hsig_s"])

        # ground station: both halves, keyed by ss_gu which we decapsulate now
        self.ss_gu = self._t("kem_decaps", KEM.decaps, d["c_gu"], self.sk_kappa)
        self._verify("ground", gs_cert.pk_sigma, self.ss_gu, P.h(self.pi3), d["hsig_g"])

        # the two session secrets addressed to this user's ephemeral key
        self.k_su = self._t("kem_decaps", KEM.decaps, d["e_su"], self.esk_u)
        self.k_gu = self._t("kem_decaps", KEM.decaps, d["e_gu"], self.esk_u)
        tag = P.tag_u(self.k_su, self.k_gu, self.ss_us, self.ss_gu, self.mu_u, self.mu_s, self.mu_g)
        self.state = "sent5"
        return [("sat", P.enc_msg5(tag))]

    def _on_msg7(self, b):
        d = P.dec_msg7_fwd(b)
        w_gu = P.wrap_key_gu(self.k_gu, self.ss_gu)
        pt = self._t("unwrap", P.unwrap, w_gu, self.mu_u, self.mu_s, self.mu_g, P.W_GS_U, d["c_gs_u"])
        if pt is None:
            raise HandshakeFailed("wrap from ground station rejected")
        k_gs, ss_sg = pt[:32], pt[32:]
        digest, hsig_s = self.deferred_s
        if not P.verify_kem_half(ss_sg, digest, hsig_s):
            raise HandshakeFailed("satellite KEM half rejected")
        self.sk = P.session_key(self.k_su, k_gs, self.k_gu, self.ss_us, ss_sg, self.ss_gu,
                                self.mu_u, self.mu_s, self.mu_g, self.ident, self.id_sat, self.id_gs, self.pi3)
        if d["tag_g"] != P.tag_g(self.sk, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("ground station confirmation tag rejected")
        if d["tag_s"] != P.tag_s(self.sk, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("satellite confirmation tag rejected")
        self._erase("esk_u", "epk_u", "k_su", "k_gu", "ss_us", "ss_gu")
        self.state = "done"
        return [("sat", P.enc_msg8(P.tag_u_final(self.sk, self.mu_u, self.mu_s, self.mu_g)))]


# ------------------------------------------------------------------ satellite

class SatelliteSession(_Role):
    """One handshake in progress per user identity."""

    def __init__(self, bundle, id_gs, **kw):
        super().__init__(bundle, **kw)
        self.id_gs = id_gs
        self.seen = {}            # replay cache: user nonce -> time accepted, inside 2 x freshness window
        self.replays_rejected = 0

    def handle(self, b, from_role):
        t = b[1]
        if t == P.MSG1 and from_role == "ue":
            return self._on_msg1(b)
        if t == P.MSG3 and from_role == "gs" and self.state == "sent2":
            return self._on_msg3(b)
        if t == P.MSG5 and from_role == "ue" and self.state == "sent4":
            return self._on_msg5(b)
        if t == P.MSG7 and from_role == "gs" and self.state == "sent6":
            return self._on_msg7(b)
        if t == P.MSG8 and from_role == "ue" and self.state == "sent7":
            return self._on_msg8(b)
        if t == P.DEMAND and from_role == "gs" and self.state == "sent2":
            self.note("demand", "ground station lacks a certificate, resending MSG2 in full")
            return [("gs", self._msg2(full=True))]
        if t == P.DEMAND and from_role == "ue" and self.state == "sent4":
            self.note("demand", "user lacks a certificate, resending MSG4 in full")
            return [("ue", self._msg4(full=True))]
        raise HandshakeFailed(f"satellite: unexpected {t:#x} from {from_role} in state {self.state}")

    def _msg2(self, full):
        ue_cert = self.cache[self.id_ue]
        return P.enc_msg2(P.encode_cert_field(ue_cert, full or self.ue_cert_full), P.h(self.c_us), self.epk_u,
                          self.mu_u, self.t1, self.hsig_u, P.encode_cert_field(self.cert, full or self.full_certs),
                          self.c_sg, self.epk_s, self.e_su, self.mu_s, self.t2, self.hsig_s)

    def _msg4(self, full):
        m3 = self.msg3
        gs_cert = self.cache[self.id_gs]
        return P.enc_msg4(P.encode_cert_field(self.cert, full or self.full_certs), P.h(self.c_sg),
                          P.h(self.epk_s), self.e_su, self.mu_s, self.t2, self.hsig_s,
                          P.encode_cert_field(gs_cert, full or m3["cert_mode"] == P.CERT_MODE_FULL),
                          m3["c_gu"], P.h(m3["e_gs"]), m3["e_gu"], m3["mu_g"], m3["t3"], m3["hsig_g"])

    def _on_msg1(self, b):
        d = P.dec_msg1(b)
        if d["id_sat"] != self.ident or d["id_gs"] != self.id_gs:
            raise HandshakeFailed("MSG1 addressed to another satellite or ground station")
        self._fresh(d["t1"])
        now = self.clock()
        self.seen = {mu: t for mu, t in self.seen.items() if now - t <= 2 * P.FRESHNESS_S}
        if d["mu_u"] in self.seen:
            self.replays_rejected += 1
            raise HandshakeFailed("replayed MSG1")
        try:
            ue_cert = self.resolve_cert(d["cert_mode"], d["cert"], d["id_ue"], P.ROLE_UE)
        except HandshakeFailed as e:
            if isinstance(e.args[0], tuple) and e.args[0][0] == "unknown certificate":
                return [("ue", P.enc_demand())]
            raise
        self.id_ue, self.mu_u, self.t1, self.c_us = d["id_ue"], d["mu_u"], d["t1"], d["c_us"]
        self.ue_cert_full = d["cert_mode"] == P.CERT_MODE_FULL
        self.hsig_u = d["hsig_u"]

        self.ss_us = self._t("kem_decaps", KEM.decaps, d["c_us"], self.sk_kappa)
        self.epk_u = d["epk_u"]
        self.pi1 = P.transcript1(self.id_ue, self.ident, self.id_gs, ue_cert.omega, P.h(d["c_us"]),
                                 P.h(d["epk_u"]), d["mu_u"], d["t1"])
        self._verify("user", ue_cert.pk_sigma, self.ss_us, P.h(self.pi1), d["hsig_u"])

        gs_cert = self.cache.get(self.id_gs)
        if gs_cert is None:
            raise HandshakeFailed("satellite holds no certificate for the ground station")
        self._role_ok(gs_cert, P.ROLE_GS)
        self.mu_s, self.t2 = secrets.token_bytes(P.NONCE_LEN), self.clock()
        self.c_sg, self.ss_sg = self._t("kem_encaps", KEM.encaps, gs_cert.pk_kappa)
        # session secret for the user under the user's ephemeral key, and our own ephemeral key pair
        self.e_su, self.k_su = self._t("kem_encaps", KEM.encaps, self.epk_u)
        self.epk_s, self.esk_s = self._t("kem_keygen", KEM.keypair)
        self.pi2 = P.transcript2(self.pi1, self.ident, self.omega, P.h(self.c_sg), P.h(self.epk_s),
                                 P.h(self.e_su), self.mu_s, self.t2)
        self.hsig_s = self._t("hybrid_sign", P.hybrid_sign, self.sk_sigma, self.ss_sg, P.h(self.pi2))

        self.seen[self.mu_u] = now
        self.state = "sent2"
        return [("gs", self._msg2(full=False))]

    def _on_msg3(self, b):
        d = P.dec_msg3(b)
        self._fresh(d["t3"])
        gs_cert = self.resolve_cert(d["cert_mode"], d["cert"], self.id_gs, P.ROLE_GS)
        self.mu_g = d["mu_g"]
        self.pi3 = P.transcript3(self.pi2, self.id_gs, gs_cert.omega, P.h(d["c_gu"]), P.h(d["e_gs"]),
                                 P.h(d["e_gu"]), d["mu_g"], d["t3"])
        # ML-DSA half now; KEM half keyed by ss_gu, delivered in MSG7
        self._verify("ground", gs_cert.pk_sigma, None, P.h(self.pi3), d["hsig_g"], require_kem=False)
        self.deferred_g = (P.h(self.pi3), d["hsig_g"])

        # session secret from the ground station under our ephemeral key.  The wrap key takes it
        # and ss_sg, and the wrap carries the two secrets the ground station lacks
        self.k_gs = self._t("kem_decaps", KEM.decaps, d["e_gs"], self.esk_s)
        self.w_sg = P.wrap_key_sg(self.k_gs, self.ss_sg)
        self.c_su_g = self._t("wrap", P.wrap, self.w_sg, self.mu_u, self.mu_s, self.mu_g, P.W_SU_G,
                              self.k_su + self.ss_us)
        self.msg3 = d
        self.state = "sent4"
        return [("ue", self._msg4(full=False))]

    def _on_msg5(self, b):
        d = P.dec_msg5(b)
        self.tag_u = d["tag_u"]
        self.state = "sent6"
        return [("gs", P.enc_msg6(self.c_su_g, d["tag_u"]))]

    def _on_msg7(self, b):
        d = P.dec_msg7(b)
        pt = self._t("unwrap", P.unwrap, self.w_sg, self.mu_u, self.mu_s, self.mu_g, P.W_GU_S, d["c_gu_s"])
        if pt is None:
            raise HandshakeFailed("wrap from ground station rejected")
        k_gu, ss_gu = pt[:32], pt[32:]
        digest, hsig_g = self.deferred_g
        if not P.verify_kem_half(ss_gu, digest, hsig_g):
            raise HandshakeFailed("ground station KEM half rejected")
        self.sk = P.session_key(self.k_su, self.k_gs, k_gu, self.ss_us, self.ss_sg, ss_gu,
                                self.mu_u, self.mu_s, self.mu_g, self.id_ue, self.ident, self.id_gs, self.pi3)
        if d["tag_g"] != P.tag_g(self.sk, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("ground station confirmation tag rejected")
        self.tag_s = P.tag_s(self.sk, self.mu_u, self.mu_s, self.mu_g)
        self._erase("esk_s", "epk_s", "k_su", "k_gs", "ss_us", "ss_sg", "w_sg")
        self.state = "sent7"
        return [("ue", P.enc_msg7_fwd(d["c_gs_u"], d["tag_g"], self.tag_s))]

    def _on_msg8(self, b):
        d = P.dec_msg8(b)
        if d["tag_u2"] != P.tag_u_final(self.sk, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("user final confirmation rejected")
        self.state = "done"
        # forwarded with the satellite's own confirmation of SK
        return [("gs", P.enc_msg8_fwd(d["tag_u2"], self.tag_s))]


# ------------------------------------------------------------------ ground

class GroundSession(_Role):
    def handle(self, b):
        t = b[1]
        if t == P.MSG2:
            return self._on_msg2(b)
        if t == P.MSG6 and self.state == "sent3":
            return self._on_msg6(b)
        if t == P.MSG8_FWD and self.state == "sent7":
            return self._on_msg8(b)
        raise HandshakeFailed(f"ground: unexpected {t:#x} in state {self.state}")

    def _on_msg2(self, b):
        d = P.dec_msg2(b)
        self._fresh(d["t1"])
        self._fresh(d["t2"])
        # resolve the satellite first, then the user; a reference we do not hold
        # gets a demand back through the satellite
        smode, scert = d["sat_cert_mode"], d["sat_cert"]
        if smode == P.CERT_MODE_FULL:
            sat_cert = P.Certificate.from_bundle(scert)
            if not self._t("cert_verify", sat_cert.verify, self.ta_pk, None, self.clock()):
                raise HandshakeFailed("satellite certificate rejected")
            self._not_revoked(sat_cert.ident)
            self._role_ok(sat_cert, P.ROLE_SAT)
            self.cache[sat_cert.ident] = sat_cert
        else:
            self._not_revoked(int.from_bytes(scert[:2], "big"))
            sat_cert = self.cache.get(int.from_bytes(scert[:2], "big"))
            if sat_cert is None or sat_cert.digest() != scert[2:]:
                return [("sat", P.enc_demand())]
            self._role_ok(sat_cert, P.ROLE_SAT)
        umode, ucert = d["ue_cert_mode"], d["ue_cert"]
        if umode == P.CERT_MODE_FULL:
            ue_cert = P.Certificate.from_bundle(ucert)
            if not self._t("cert_verify", ue_cert.verify, self.ta_pk, None, self.clock()):
                raise HandshakeFailed("user certificate rejected")
            self._not_revoked(ue_cert.ident)
            self._role_ok(ue_cert, P.ROLE_UE)
            self.cache[ue_cert.ident] = ue_cert
        else:
            self._not_revoked(int.from_bytes(ucert[:2], "big"))
            ue_cert = self.cache.get(int.from_bytes(ucert[:2], "big"))
            if ue_cert is None or ue_cert.digest() != ucert[2:]:
                return [("sat", P.enc_demand())]
            self._role_ok(ue_cert, P.ROLE_UE)

        self.id_ue, self.id_sat = ue_cert.ident, sat_cert.ident
        self.mu_u, self.mu_s = d["mu_u"], d["mu_s"]

        # Π1 from the user's fields, using h(c_us) as forwarded (Change 1)
        pi1 = P.transcript1(self.id_ue, self.id_sat, self.ident, ue_cert.omega, d["h_c_us"], P.h(d["epk_u"]),
                            d["mu_u"], d["t1"])
        # ss_us reaches the ground station only in MSG6: the ML-DSA half of the user's signature
        # is verified here, and tag_u in MSG6 covers ss_us and ss_gu
        self._verify("user", ue_cert.pk_sigma, None, P.h(pi1), d["hsig_u"], require_kem=False)

        pi2 = P.transcript2(pi1, self.id_sat, sat_cert.omega, P.h(d["c_sg"]), P.h(d["epk_s"]), P.h(d["e_su"]),
                            d["mu_s"], d["t2"])
        self.ss_sg = self._t("kem_decaps", KEM.decaps, d["c_sg"], self.sk_kappa)
        self._verify("satellite", sat_cert.pk_sigma, self.ss_sg, P.h(pi2), d["hsig_s"])

        self.mu_g, self.t3 = secrets.token_bytes(P.NONCE_LEN), self.clock()
        self.c_gu, self.ss_gu = self._t("kem_encaps", KEM.encaps, ue_cert.pk_kappa)
        # session secrets under the two ephemeral keys, both bound by the signatures just verified
        self.e_gs, self.k_gs = self._t("kem_encaps", KEM.encaps, d["epk_s"])
        self.e_gu, self.k_gu = self._t("kem_encaps", KEM.encaps, d["epk_u"])
        self.pi3 = P.transcript3(pi2, self.ident, self.omega, P.h(self.c_gu), P.h(self.e_gs), P.h(self.e_gu),
                                 self.mu_g, self.t3)
        hsig_g = self._t("hybrid_sign", P.hybrid_sign, self.sk_sigma, self.ss_gu, P.h(self.pi3))
        self.state = "sent3"
        return [("sat", P.enc_msg3(self.cert_field(), self.c_gu, self.e_gs, self.e_gu, self.mu_g, self.t3,
                                   hsig_g))]

    def _on_msg6(self, b):
        d = P.dec_msg6(b)
        w_sg = P.wrap_key_sg(self.k_gs, self.ss_sg)
        pt = self._t("unwrap", P.unwrap, w_sg, self.mu_u, self.mu_s, self.mu_g, P.W_SU_G, d["c_su_g"])
        if pt is None:
            raise HandshakeFailed("wrap from satellite rejected")
        k_su, ss_us = pt[:32], pt[32:]
        # tag_u first: it shows that the real user (ss_gu) and the real satellite (ss_us) take part.
        # Only then are ss_gu and ss_sg released in the wraps below; the proof relies on this order.
        if d["tag_u"] != P.tag_u(k_su, self.k_gu, ss_us, self.ss_gu, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("user partial confirmation rejected")
        self.sk = P.session_key(k_su, self.k_gs, self.k_gu, ss_us, self.ss_sg, self.ss_gu,
                                self.mu_u, self.mu_s, self.mu_g, self.id_ue, self.id_sat, self.ident, self.pi3)
        w_gu = P.wrap_key_gu(self.k_gu, self.ss_gu)
        c_gs_u = self._t("wrap", P.wrap, w_gu, self.mu_u, self.mu_s, self.mu_g, P.W_GS_U, self.k_gs + self.ss_sg)
        c_gu_s = self._t("wrap", P.wrap, w_sg, self.mu_u, self.mu_s, self.mu_g, P.W_GU_S, self.k_gu + self.ss_gu)
        tag = P.tag_g(self.sk, self.mu_u, self.mu_s, self.mu_g)
        self._erase("k_gs", "k_gu", "ss_sg", "ss_gu")
        self.state = "sent7"
        return [("sat", P.enc_msg7(c_gs_u, c_gu_s, tag))]

    def _on_msg8(self, b):
        d = P.dec_msg8_fwd(b)
        if d["tag_u2"] != P.tag_u_final(self.sk, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("user final confirmation rejected")
        if d["tag_s"] != P.tag_s(self.sk, self.mu_u, self.mu_s, self.mu_g):
            raise HandshakeFailed("satellite confirmation rejected")
        self.state = "done"
        return []

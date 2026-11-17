"""Attack classes at the protocol layer (no link): Python roles and the flight C satellite.

    B1  man in the middle: substituted KEM ciphertext, substituted ephemeral keys and
        substituted session ciphertexts
    B2  downgrade: a message relabelled as an older version, and a message in the older layout
    B3  session state: what an adversary learns from long term keys after the handshake
        (forward secrecy) and from single session secrets
    B4  revocation: a revoked identity, a forged list, an old list, and the window before
        the list is distributed
    B5  replay of later handshake messages (MSG3, MSG5, MSG7) from an earlier run

Run:  python3 test_attacks_protocol.py     (needs ./authsim, built as in test_interop.py)
"""
import json
import os
import pickle
import subprocess
import sys
import time

import pqsat
import pqsat_proto as P
from pqsat import ML_KEM_768 as KEM
from pqsat_roles import UserSession, SatelliteSession, GroundSession, HandshakeFailed

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(HERE, "keys")
ID_GS, ID_UE, ID_SAT = 0x0001, 0x0011, 0x0101
results = []


def check(name, cond, note=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{note}]" if note else ""), flush=True)


def provision(full=True):
    ta = P.TrustedAuthority()
    b = {n: ta.enrol(i, r) for n, i, r in (("sat", ID_SAT, P.ROLE_SAT), ("gs", ID_GS, P.ROLE_GS), ("ue", ID_UE, P.ROLE_UE))}
    ue = UserSession(b["ue"], full_certs=full)
    sat = SatelliteSession(b["sat"], ID_GS, full_certs=full)
    gs = GroundSession(b["gs"], full_certs=full)
    ue.cache[ID_SAT] = b["sat"]["cert"]
    sat.cache[ID_GS] = b["gs"]["cert"]
    return ta, b, ue, sat, gs


def run(ue, sat, gs, mangle=None, record=None):
    """mangle(step, src, dst, msg) -> msg lets the adversary rewrite any message in flight."""
    q = [("ue", d, m) for d, m in ue.start(ID_SAT, ID_GS)]
    roles, step = {"ue": ue, "gs": gs}, 0
    while q:
        src, dst, m = q.pop(0)
        step += 1
        if record is not None:
            record.append((step, src, dst, m))
        if mangle:
            m = mangle(step, src, dst, m)
        out = sat.handle(m, src) if dst == "sat" else roles[dst].handle(m)
        q.extend((dst, d2, m2) for d2, m2 in out)


def rejected(fn):
    try:
        fn()
        return None
    except (HandshakeFailed, P.ProtocolError) as e:
        return str(e.args[0])


def splice(m, off, new):
    return m[:off] + new + m[off + len(new):]


# offsets in the full certificate layout
CF = 1 + P.CERT_BUNDLE_LEN
M1_CUS, M1_EPK = 2 + 6 + CF, 2 + 6 + CF + 1088
M2_EPKU = 2 + CF + 32
M2_SAT = M2_EPKU + 1184 + 32 + 4 + P.HSIG_LEN + CF            # c_sg
M2_EPKS, M2_ESU = M2_SAT + 1088, M2_SAT + 1088 + 1184
M3_EGS, M3_EGU = 2 + CF + 1088, 2 + CF + 2176
M4_ESU = 2 + CF + 64
M4_EGU = M4_ESU + 1088 + 32 + 4 + P.HSIG_LEN + CF + 1088 + 32

print("--- B1 man in the middle ---")
adv_pk, adv_sk = KEM.keypair()
for name, step, off, make in (
        ("own ciphertext in place of c_us (MSG1)", 1, M1_CUS, lambda b: KEM.encaps(b["sat"]["cert"].pk_kappa)[0]),
        ("own ephemeral key in place of epk_u (MSG1)", 1, M1_EPK, lambda b: adv_pk),
        ("own ephemeral key in place of epk_u (MSG2, towards the ground)", 2, M2_EPKU, lambda b: adv_pk),
        ("own ephemeral key in place of epk_s (MSG2)", 2, M2_EPKS, lambda b: adv_pk),
        ("own session ciphertext in place of e_su (MSG2)", 2, M2_ESU, lambda b: KEM.encaps(adv_pk)[0]),
        ("own session ciphertext in place of e_gs (MSG3)", 3, M3_EGS, lambda b: KEM.encaps(adv_pk)[0]),
        ("own session ciphertext in place of e_gu (MSG3)", 3, M3_EGU, lambda b: KEM.encaps(adv_pk)[0]),
        ("own session ciphertext in place of e_su (MSG4)", 4, M4_ESU, lambda b: KEM.encaps(adv_pk)[0]),
        ("own session ciphertext in place of e_gu (MSG4)", 4, M4_EGU, lambda b: KEM.encaps(adv_pk)[0])):
    ta, b, ue, sat, gs = provision()
    r = rejected(lambda: run(ue, sat, gs, lambda s, a, d, m: splice(m, off, make(b)) if s == step else m))
    check(f"B1 {name}: rejected, no session key anywhere", r is not None and ue.sk is None and gs.sk is None
          and sat.sk is None, r or "ACCEPTED")

print("--- B2 downgrade ---")
ta, b, ue, sat, gs = provision()
r = rejected(lambda: run(ue, sat, gs, lambda s, a, d, m: bytes([0x01]) + m[1:] if s == 1 else m))
check("B2 MSG1 relabelled as version 1: rejected", r is not None, r or "ACCEPTED")
ta, b, ue, sat, gs = provision()
r = rejected(lambda: run(ue, sat, gs, lambda s, a, d, m: bytes([0x02]) + m[1:] if s == 1 else m))
check("B2 MSG1 relabelled as version 2: rejected", r is not None, r or "ACCEPTED")
ta, b, ue, sat, gs = provision()
r = rejected(lambda: run(ue, sat, gs, lambda s, a, d, m: bytes([0x01]) + m[1:M1_EPK] + m[M1_EPK + 1184:] if s == 1 else m))
check("B2 MSG1 cut down to the older layout (no ephemeral key): rejected", r is not None, r or "ACCEPTED")
ta, b, ue, sat, gs = provision()
r = rejected(lambda: run(ue, sat, gs, lambda s, a, d, m: m[:M1_EPK] + m[M1_EPK + 1184:] if s == 1 else m))
check("B2 ephemeral key stripped, version left unchanged: rejected", r is not None, r or "ACCEPTED")

print("--- B3 session state and forward secrecy ---")
ta, b, ue, sat, gs = provision()
rec = []
run(ue, sat, gs, record=rec)
SK = ue.sk
check("B3 reference handshake completed", SK is not None and SK == sat.sk == gs.sk)
msg = {s: m for s, _, _, m in rec}
m1, m2, m3, m6, m7 = P.dec_msg1(msg[1]), P.dec_msg2(msg[2]), P.dec_msg3(msg[3]), P.dec_msg6(msg[6]), P.dec_msg7(msg[7])
nonces = (m1["mu_u"], m2["mu_s"], m3["mu_g"])
# the adversary recorded everything and later obtains every long term secret key
ss_us = KEM.decaps(m1["c_us"], b["sat"]["sk_kappa"])
ss_sg = KEM.decaps(m2["c_sg"], b["gs"]["sk_kappa"])
ss_gu = KEM.decaps(m3["c_gu"], b["ue"]["sk_kappa"])
WRAPS = lambda m6, m7: [(m6["c_su_g"], P.W_SU_G, "sg"), (m7["c_gs_u"], P.W_GS_U, "gu"), (m7["c_gu_s"], P.W_GU_S, "sg")]
zero = bytes(32)
tries = [k for ss in (ss_us, ss_sg, ss_gu) for k in (ss, P.wrap_key_sg(zero, ss), P.wrap_key_gu(zero, ss),
                                                     P.wrap_key_sg(ss, ss), P.wrap_key_gu(ss, ss))]
opened = [P.unwrap(k, *nonces, label, w) for k in tries for w, label, _ in WRAPS(m6, m7)]
check("B3 forward secrecy: all long term keys compromised after the handshake, the three authentication "
      "secrets are recovered but open none of the three wraps", all(o is None for o in opened))
check("B3 ephemeral secret keys, session secrets and authentication secrets are erased on all three nodes",
      ue.esk_u is None and sat.esk_s is None and ue.k_su is None and sat.k_gs is None and gs.k_gu is None
      and ue.ss_us is None and sat.ss_sg is None and gs.ss_gu is None)


def leak(ue, sat, gs):
    """Run a handshake and hand the adversary every secret taken just before erasure."""
    grab = {}
    orig = {r: r._erase for r in (ue, sat, gs)}

    def hook(role):
        def e(*names):
            for n in ("k_su", "k_gs", "k_gu", "ss_us", "ss_sg", "ss_gu"):
                if getattr(role, n, None):
                    grab[n] = getattr(role, n)
            orig[role](*names)
        return e
    for r in (ue, sat, gs):
        r._erase = hook(r)
    rec = []
    run(ue, sat, gs, record=rec)
    return grab, {s: m for s, _, _, m in rec}


def closure(known, msgs):
    """Everything derivable from the given secrets and the recorded messages."""
    m1, m2, m3 = P.dec_msg1(msgs[1]), P.dec_msg2(msgs[2]), P.dec_msg3(msgs[3])
    m6, m7 = P.dec_msg6(msgs[6]), P.dec_msg7(msgs[7])
    n = (m1["mu_u"], m2["mu_s"], m3["mu_g"])
    have = dict(known)
    for _ in range(4):
        for kk, sk_, mk, w, label, out in (
                ("k_gs", "ss_sg", P.wrap_key_sg, m6["c_su_g"], P.W_SU_G, ("k_su", "ss_us")),
                ("k_gu", "ss_gu", P.wrap_key_gu, m7["c_gs_u"], P.W_GS_U, ("k_gs", "ss_sg")),
                ("k_gs", "ss_sg", P.wrap_key_sg, m7["c_gu_s"], P.W_GU_S, ("k_gu", "ss_gu"))):
            if kk in have and sk_ in have:
                v = P.unwrap(mk(have[kk], have[sk_]), *n, label, w)
                if v is not None:
                    have[out[0]], have[out[1]] = v[:32], v[32:]
    return have


ALL6 = {"k_su", "k_gs", "k_gu", "ss_us", "ss_sg", "ss_gu"}
ta, b, ue, sat, gs = provision()
g, msgs = leak(ue, sat, gs)
for which in ("k_su", "k_gs", "k_gu"):
    got = closure({which: g[which]}, msgs)
    check(f"B3 leak of {which} alone: adversary obtains nothing more, session key stays secret", set(got) == {which})
got = closure({k: g[k] for k in ("k_su", "k_gs", "k_gu")}, msgs)
check("B3 leak of all three session secrets (every ephemeral key broken): no wrap opens, the authentication "
      "secrets and the session key stay secret", set(got) == {"k_su", "k_gs", "k_gu"})
got = closure({k: g[k] for k in ("ss_us", "ss_sg", "ss_gu")}, msgs)
check("B3 leak of all three authentication secrets (every long term ML-KEM key broken): no wrap opens, the "
      "session secrets and the session key stay secret", set(got) == {"ss_us", "ss_sg", "ss_gu"})
got = closure({"k_gs": g["k_gs"], "ss_sg": g["ss_sg"]}, msgs)
check("B3 limit: one session secret AND the authentication secret of the same pair (k_gs with ss_sg) open the "
      "wraps and give all six secrets", set(got) == ALL6)

print("--- B4 revocation ---")
ta, b, ue, sat, gs = provision()
r = rejected(lambda: run(ue, sat, gs))
check("B4 before any list is distributed the revoked user is still accepted (the suppression window)", r is None)
crl = ta.issue_crl([ID_UE])
ta, b, ue, sat, gs = provision()
crl = ta.issue_crl([ID_UE])
check("B4 list signed by the authority installs on the satellite", sat.install_crl(crl) == 1)
r = rejected(lambda: run(ue, sat, gs))
check("B4 revoked user rejected by the satellite, full certificate", r is not None and sat.sk is None, r or "ACCEPTED")
ta, b, ue, sat, gs = provision(full=False)
sat.cache[ID_UE] = b["ue"]["cert"]; gs.cache[ID_UE] = b["ue"]["cert"]; gs.cache[ID_SAT] = b["sat"]["cert"]
ue.cache[ID_GS] = b["gs"]["cert"]
sat.install_crl(ta.issue_crl([ID_UE]))
r = rejected(lambda: run(ue, sat, gs))
check("B4 revoked user rejected by the satellite, cached reference", r is not None, r or "ACCEPTED")
ta, b, ue, sat, gs = provision()
gs.install_crl(ta.issue_crl([ID_UE]))
r = rejected(lambda: run(ue, sat, gs))
check("B4 satellite without the list forwards, ground station with the list rejects the revoked user",
      r is not None and gs.sk is None, r or "ACCEPTED")
ta, b, ue, sat, gs = provision()
ue.install_crl(ta.issue_crl([ID_SAT]))
r = rejected(lambda: run(ue, sat, gs))
check("B4 user rejects a revoked satellite", r is not None, r or "ACCEPTED")
other = P.TrustedAuthority()
ta, b, ue, sat, gs = provision()
r = rejected(lambda: sat.install_crl(other.issue_crl([ID_UE])))
check("B4 list signed by another authority refused", r is not None, r or "ACCEPTED")
good = ta.issue_crl([ID_UE], issued=2000)
bad = bytearray(good); bad[9] ^= 1
r = rejected(lambda: sat.install_crl(bytes(bad)))
check("B4 list with a changed identity refused", r is not None, r or "ACCEPTED")
sat.install_crl(good)
r = rejected(lambda: sat.install_crl(ta.issue_crl([], issued=1000)))
check("B4 older empty list cannot undo a revocation", r is not None and ID_UE in sat.revoked, r or "ACCEPTED")

print("--- B5 replay of later messages from an earlier handshake ---")
ta, b, ue, sat, gs = provision()
old = []
run(ue, sat, gs, record=old)
oldm = {s: m for s, _, _, m in old}
for step in (3, 5, 7):
    ue2 = UserSession(b["ue"]); ue2.cache[ID_SAT] = b["sat"]["cert"]
    sat2 = SatelliteSession(b["sat"], ID_GS); sat2.cache[ID_GS] = b["gs"]["cert"]
    gs2 = GroundSession(b["gs"])
    r = rejected(lambda: run(ue2, sat2, gs2, lambda s, a, d, m: oldm[step] if s == step else m))
    check(f"B5 MSG{step} of an earlier handshake replayed into a new one: rejected", r is not None
          and not (ue2.sk and ue2.sk == sat2.sk == gs2.sk), r or "ACCEPTED")

# ---------------------------------------------------------------- the same against the flight C satellite
print("--- flight C satellite (authsim) ---")
AUTHSIM = os.path.join(HERE, "authsim")
if not os.path.exists(AUTHSIM):
    print("SKIP authsim not built")
else:
    def load(n):
        with open(os.path.join(KEYS, n + ".pickle"), "rb") as f:
            return pickle.load(f)

    class CSat:
        def __init__(self):
            self.p = subprocess.Popen([AUTHSIM, os.path.join(KEYS, "sat1.bundle"), os.path.join(KEYS, "gs.cert"), "full"],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
            self.logs = []
            self._read(first=True)

        def _read(self, first=False):
            out = []
            while True:
                line = self.p.stdout.readline().rstrip("\n")
                if line.startswith("LOG,"):
                    self.logs.append(line[4:])
                    if first:
                        return out
                elif line == "OK" or line == "":
                    return out
                elif line.startswith("S,"):
                    _, dst, hx = line.split(",", 2)
                    out.append((int(dst, 16), bytes.fromhex(hx)))

        def handle(self, frm, m):
            self.p.stdin.write(f"M,{frm:04X},{int(time.time())},{m.hex().upper()}\n"); self.p.stdin.flush()
            return self._read()

        def close(self):
            self.p.stdin.write("Q\n"); self.p.stdin.flush(); self.p.wait()

    b_ue, b_gs, b_sat = load("ue1"), load("gs"), load("sat1")
    ta_keys = json.load(open(os.path.join(KEYS, "ta.json")))

    def user():
        u = UserSession(b_ue); u.cache[ID_SAT] = b_sat["cert"]; return u

    for name, off, new in (("own ciphertext in place of c_us", M1_CUS, KEM.encaps(b_sat["cert"].pk_kappa)[0]),
                           ("own ephemeral key in place of epk_u", M1_EPK, adv_pk)):
        s = CSat(); m1 = user().start(ID_SAT, ID_GS)[0][1]
        out = s.handle(ID_UE, splice(m1, off, new))
        check(f"C  B1 {name}: no MSG2 produced", not out, s.logs[-1]); s.close()
    s = CSat(); m1 = user().start(ID_SAT, ID_GS)[0][1]
    out = s.handle(ID_UE, bytes([0x01]) + m1[1:])
    check("C  B2 version 1 label on MSG1: ignored", not out, s.logs[-1]); s.close()
    s = CSat()
    out = s.handle(ID_GS, P.enc_crl(P.TrustedAuthority().sk_sigma, [ID_UE]))
    check("C  B4 list signed by another authority refused", any("does not verify" in l for l in s.logs), s.logs[-1])
    out = s.handle(ID_UE, user().start(ID_SAT, ID_GS)[0][1])
    check("C  B4 user still accepted before a valid list arrives", len(out) == 1 and out[0][1][1] == P.MSG2)
    s.handle(ID_GS, P.enc_crl(bytes.fromhex(ta_keys["sk_sigma"]), [ID_UE]))
    check("C  B4 list signed by the authority installed over the link", any("revocation list installed" in l for l in s.logs),
          s.logs[-1])
    out = s.handle(ID_UE, user().start(ID_SAT, ID_GS)[0][1])
    check("C  B4 revoked user rejected, no MSG2", not out and any("revocation list" in l for l in s.logs[-3:]), s.logs[-1])
    s.handle(ID_GS, P.enc_crl(bytes.fromhex(ta_keys["sk_sigma"]), [], issued=1000))
    out = s.handle(ID_UE, user().start(ID_SAT, ID_GS)[0][1])
    check("C  B4 older empty list cannot undo the revocation", not out, s.logs[-1]); s.close()

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

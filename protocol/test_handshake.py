"""Phase 5 in process: three roles, no transport.  Proves the cryptographic
logic end to end before any link is involved, and checks message sizes against
the specification."""
import sys
import pqsat_proto as P
from pqsat_roles import UserSession, SatelliteSession, GroundSession, HandshakeFailed

ID_GS, ID_UE, ID_SAT = 0x0001, 0x0011, 0x0101
fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    fails += 0 if cond else 1


def provision(full_certs=True):
    ta = P.TrustedAuthority()
    b_sat, b_gs, b_ue = ta.enrol(ID_SAT, P.ROLE_SAT), ta.enrol(ID_GS, P.ROLE_GS), ta.enrol(ID_UE, P.ROLE_UE)
    ue = UserSession(b_ue, full_certs=full_certs)
    sat = SatelliteSession(b_sat, ID_GS, full_certs=full_certs)
    gs = GroundSession(b_gs, full_certs=full_certs)
    # what each node holds before any contact: the certificates it must address
    ue.cache[ID_SAT] = b_sat["cert"]
    sat.cache[ID_GS] = b_gs["cert"]
    return ta, ue, sat, gs


def run(ue, sat, gs, sizes=None, tamper=None):
    """Drive messages between the roles until nobody has anything to send."""
    queue = [("ue", dest, b) for dest, b in ue.start(ID_SAT, ID_GS)]
    roles = {"ue": ue, "sat": sat, "gs": gs}
    step = 0
    while queue:
        src, dest, b = queue.pop(0)
        step += 1
        if sizes is not None:
            sizes.append((b[1], len(b)))
        if tamper and tamper[0] == step:
            b = bytearray(b); b[tamper[1]] ^= 0x01; b = bytes(b)
        # on the real link the source is the virtual channel the frame arrived on
        out = sat.handle(b, src) if dest == "sat" else roles[dest].handle(b)
        queue.extend((dest, d2, b2) for d2, b2 in out)
    return step


# ---- full certificates ----
ta, ue, sat, gs = provision(True)
sizes = []
n = run(ue, sat, gs, sizes)
check("handshake completes, full certificates", ue.state == gs.state == sat.state == "done")
check("all three derive the same session key", ue.sk == sat.sk == gs.sk and ue.sk is not None)
print("   messages:", n, " SK =", ue.sk.hex()[:32], "...")
by_type = {t: n for t, n in sizes}
print("   sizes:", {f"{t:#04x}": n for t, n in sizes})
check("MSG1 full = 13266", by_type[P.MSG1] == 13266)
check("MSG2 full = 26550", by_type[P.MSG2] == 26550)
check("MSG3 full = 14252", by_type[P.MSG3] == 14252)
check("MSG4 full = 25334", by_type[P.MSG4] == 25334)
check("MSG5 34, MSG6 114, MSG7 194, MSG7f 146, MSG8 34, MSG8 forwarded 66",
      [by_type[t] for t in (P.MSG5, P.MSG6, P.MSG7, P.MSG7_FWD, P.MSG8, P.MSG8_FWD)] == [34, 114, 194, 146, 34, 66])
check("handshake total, full certificates = 79924 (MSG8 counted once)", sum(n for t, n in sizes if t != P.MSG8_FWD) == 79924)

# ---- referenced certificates after first contact ----
ta, ue, sat, gs = provision(True)
run(ue, sat, gs)
for r in (ue, sat, gs):
    r.full_certs = False; r.state = "idle"; r.sk = None
sizes = []
run(ue, sat, gs, sizes)
by_type = {t: n for t, n in sizes}
check("second contact with references completes", ue.sk == sat.sk == gs.sk and ue.sk is not None)
check("MSG1 reference = 5692", by_type[P.MSG1] == 5692)
check("MSG2 reference = 11402", by_type[P.MSG2] == 11402)
check("MSG4 reference = 10186", by_type[P.MSG4] == 10186)
print("   reference sizes:", {f"{t:#04x}": n for t, n in sizes})
check("MSG3 reference = 6678", by_type[P.MSG3] == 6678)
check("handshake total, references = 34480 (MSG8 counted once)", sum(n for t, n in sizes if t != P.MSG8_FWD) == 34480)

# ---- unknown reference triggers a demand and a full retry ----
ta, ue, sat, gs = provision(False)
sizes = []
run(ue, sat, gs, sizes)
check("unknown reference: demand then full certificate, handshake completes",
      ue.sk == sat.sk == gs.sk and ue.sk is not None and sizes[0][0] == P.MSG1 and sizes[1][0] == P.DEMAND)

# ---- negative cases ----
def expect_fail(name, **kw):
    ta, ue, sat, gs = provision(True)
    try:
        run(ue, sat, gs, **kw)
        check(name, False)
    except HandshakeFailed as e:
        check(name + f"  [{e.args[0]}]", True)

expect_fail("flipped bit in the user's ML-DSA signature (MSG1) rejected", tamper=(1, 13266 - 3341 + 10))
expect_fail("flipped bit in the user's KEM tag (MSG1) rejected", tamper=(1, 13266 - 5))
expect_fail("flipped bit in the user's certificate (MSG1) rejected", tamper=(1, 20))
expect_fail("flipped bit in the satellite's signature (MSG2) rejected", tamper=(2, 26550 - 5))
expect_fail("flipped bit in the ground station's signature (MSG3) rejected", tamper=(3, 14252 - 5))
expect_fail("flipped bit in a wrap (MSG6) rejected", tamper=(6, 10))
# the ephemeral keys and the session secret ciphertexts are bound by the signatures
M1_EPK = 2 + 6 + 7609 + 1088 + 100                       # inside epk_u in MSG1
expect_fail("flipped bit in the user's ephemeral key (MSG1) rejected", tamper=(1, M1_EPK))
M2_SAT = 2 + 7609 + 32 + 1184 + 32 + 4 + 3341 + 7609 + 1088   # start of epk_s in MSG2
expect_fail("flipped bit in the satellite's ephemeral key (MSG2) rejected", tamper=(2, M2_SAT + 100))
expect_fail("flipped bit in e_su (MSG2) rejected", tamper=(2, M2_SAT + 1184 + 100))
M3_E = 2 + 7609 + 1088                                   # start of e_gs in MSG3
expect_fail("flipped bit in e_gs (MSG3) rejected", tamper=(3, M3_E + 100))
expect_fail("flipped bit in e_gu (MSG3) rejected", tamper=(3, M3_E + 1088 + 100))
expect_fail("flipped bit in e_su (MSG4) rejected", tamper=(4, 2 + 7609 + 64 + 100))

# forward secrecy: the ephemeral secret keys, the session secrets and the authentication secrets are erased
ta, ue, sat, gs = provision(True)
run(ue, sat, gs)
check("forward secrecy: ephemeral secret keys and session secrets erased on all three nodes",
      ue.sk == sat.sk == gs.sk and ue.esk_u is None and ue.k_su is None and ue.k_gu is None
      and sat.esk_s is None and sat.k_su is None and sat.k_gs is None and gs.k_gs is None and gs.k_gu is None
      and ue.ss_us is None and ue.ss_gu is None and sat.ss_us is None and sat.ss_sg is None and sat.w_sg is None
      and gs.ss_sg is None and gs.ss_gu is None)
expect_fail("flipped bit in the wrap for the satellite (MSG7) rejected", tamper=(7, 2 + 80 + 3))
expect_fail("flipped bit in the ground confirmation tag (MSG7) rejected", tamper=(7, 2 + 160 + 3))
expect_fail("flipped bit in the wrap for the user (MSG7f) rejected", tamper=(8, 2 + 3))
expect_fail("flipped bit in the satellite confirmation tag_s (MSG7f) rejected", tamper=(8, 2 + 80 + 32 + 3))
expect_fail("flipped bit in the user confirmation tag_u (MSG5) rejected", tamper=(5, 2 + 3))
expect_fail("flipped bit in tag_u' (MSG8) rejected", tamper=(9, 2 + 3))
expect_fail("flipped bit in tag_s as forwarded to the ground (MSG8 forwarded) rejected", tamper=(10, 2 + 32 + 3))

# SK needs the authentication secrets.  An adversary that knows every session secret
# (all ephemeral keys leaked) still cannot compute SK without ss_us, ss_sg and ss_gu.
ta, ue, sat, gs = provision(True)
import pqsat
orig_erase = {r: r._erase for r in (ue, sat, gs)}
keep = {}
for r in (ue, sat, gs):
    def spy(*names, _r=r):
        for n_ in names:
            keep[(_r.__class__.__name__, n_)] = getattr(_r, n_, None)
        orig_erase[_r](*names)
    r._erase = spy
run(ue, sat, gs)
k_su, k_gu = keep[("UserSession", "k_su")], keep[("UserSession", "k_gu")]
k_gs = keep[("SatelliteSession", "k_gs")]
zero = bytes(32)
guess = P.session_key(k_su, k_gs, k_gu, zero, zero, zero, ue.mu_u, ue.mu_s, ue.mu_g, ID_UE, ID_SAT, ID_GS, ue.pi3)
check("all three session secrets without the authentication secrets do not give SK", guess != ue.sk)
real = P.session_key(k_su, k_gs, k_gu, keep[("UserSession", "ss_us")], keep[("SatelliteSession", "ss_sg")],
                     keep[("UserSession", "ss_gu")], ue.mu_u, ue.mu_s, ue.mu_g, ID_UE, ID_SAT, ID_GS, ue.pi3)
check("SK is the KDF of the three session secrets and the three authentication secrets", real == ue.sk)
check("derived keys K_gl, K_ord and SK_n differ from SK and from each other",
      len({ue.sk, P.ground_link_key(ue.sk), P.order_key(ue.sk), P.next_link_key(ue.sk, 0x0102),
           P.next_link_key(ue.sk, 0x0103)}) == 5)

# Certificate roles.  A user certificate cannot stand in the place of a satellite or a ground station.
ta = P.TrustedAuthority()
b_sat, b_gs, b_ue = ta.enrol(ID_SAT, P.ROLE_SAT), ta.enrol(ID_GS, P.ROLE_GS), ta.enrol(ID_UE, P.ROLE_UE)
b_fake_sat = ta.enrol(ID_SAT, P.ROLE_UE)          # a valid certificate of the authority, wrong role
ue = UserSession(b_ue); sat = SatelliteSession(b_fake_sat, ID_GS); gs = GroundSession(b_gs)
ue.cache[ID_SAT] = b_fake_sat["cert"]; sat.cache[ID_GS] = b_gs["cert"]
try:
    run(ue, sat, gs); check("user certificate in the place of a satellite rejected by the user", False)
except HandshakeFailed as e:
    check(f"user certificate in the place of a satellite rejected by the user  [{e.args[0]}]", "role" in str(e.args[0]))
ue = UserSession(b_ue); sat = SatelliteSession(b_fake_sat, ID_GS); gs = GroundSession(b_gs)
ue._role_ok = lambda c, r: None                     # a careless user: the ground station must still refuse
ue.cache[ID_SAT] = b_fake_sat["cert"]; sat.cache[ID_GS] = b_gs["cert"]
try:
    run(ue, sat, gs); check("user certificate in the place of a satellite rejected by the ground station", False)
except HandshakeFailed as e:
    check(f"user certificate in the place of a satellite rejected by the ground station  [{e.args[0]}]", "role" in str(e.args[0]))
b_fake_ue = ta.enrol(ID_UE, P.ROLE_SAT)
ue = UserSession(b_fake_ue); sat = SatelliteSession(b_sat, ID_GS); gs = GroundSession(b_gs)
ue.cache[ID_SAT] = b_sat["cert"]; sat.cache[ID_GS] = b_gs["cert"]
try:
    run(ue, sat, gs); check("satellite certificate in the place of a user rejected by the satellite", False)
except HandshakeFailed as e:
    check(f"satellite certificate in the place of a user rejected by the satellite  [{e.args[0]}]", "role" in str(e.args[0]))

# replayed MSG1: the same bytes a second time, inside the freshness window
ta, ue, sat, gs = provision(True)
msg1 = ue.start(ID_SAT, ID_GS)[0][1]
sat.handle(msg1, "ue")
try:
    sat.handle(msg1, "ue"); check("replayed MSG1 rejected", False)
except HandshakeFailed as e:
    check(f"replayed MSG1 rejected  [{e.args[0]}]", e.args[0] == "replayed MSG1")

# stale timestamp
ta, ue, sat, gs = provision(True)
ue.clock = lambda: int(__import__("time").time()) - 2 * P.FRESHNESS_S
try:
    run(ue, sat, gs); check("stale MSG1 rejected", False)
except HandshakeFailed as e:
    check(f"stale MSG1 rejected  [{e.args[0]}]", e.args[0] == "stale timestamp")

# wrong satellite addressed
ta, ue, sat, gs = provision(True)
try:
    ue.cache[0x0102] = ue.cache[ID_SAT]
    q = ue.start(0x0102, ID_GS); sat.handle(q[0][1], "ue"); check("MSG1 for another satellite rejected", False)
except HandshakeFailed as e:
    check(f"MSG1 for another satellite rejected  [{e.args[0]}]", True)

print(f"\n{'ALL PASSED' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)

# PQSAT authentication protocol

Three party post quantum mutual authentication and key exchange among a user terminal (UE),
its serving satellite (SAT) and a ground station (GS), followed by the constellation phase
that carries the session across the inter satellite link (ISL).

Primitives: ML-DSA-65 (signatures), ML-KEM-768 (encapsulation), SHA3-256, HKDF-SHA3-256,
HMAC-SHA3-256 and AES-256-GCM. Version octet 0x03.

Implementations in this repository, byte for byte identical across the three:

| Part | Files |
|---|---|
| Reference implementation (terminals) | `protocol/pqsat_proto.py`, `protocol/pqsat_roles.py` |
| Flight software (satellite) | `flight/apps/sat_rf/fsw/src/sat_auth.c`, `sat_ccsds.c` |
| Formal models | `formal/pqsat_handshake.spthy`, `formal/pqsat_handover.spthy` |

## Certificates

A certificate binds an identity and a role (user, satellite or ground station) to an ML-DSA-65
public key and an ML-KEM-768 public key. Every node checks the role of a certificate before it
uses it, so a user certificate cannot stand in the place of a satellite. A certificate is sent
in full or by reference (identity and digest, 34 octets) once the peer holds it.

Certificate policy: a certificate provisioned at enrollment is the trusted binding of its
identity. A certificate received in band is accepted only if it is that same certificate and
never replaces it. Where none is installed the received certificate is a candidate for that
handshake only.

## Handshake

Eight logical messages. MSG1 UE to SAT, MSG2 SAT to GS, MSG3 GS to SAT, MSG4 SAT to UE,
MSG5 UE to SAT, MSG6 SAT to GS, MSG7 GS to SAT (forwarded to the UE as MSG7f), MSG8 UE to SAT
(forwarded to the GS).

Two sets of ML-KEM secrets:

- authentication secrets, encapsulated to long term keys: ss_us (UE to SAT), ss_sg (SAT to GS),
  ss_gu (GS to UE)
- session secrets, encapsulated to ephemeral keys: k_su (SAT to epk_u), k_gs (GS to epk_s),
  k_gu (GS to epk_u)

### Session key

    SK = KDF(k_su | k_gs | k_gu | ss_us | ss_sg | ss_gu | mu_u | mu_s | mu_g | ID_UE | ID_SAT | ID_GS | Pi3, "SK")

The session secrets give forward secrecy. The authentication secrets give authentication that
does not depend on ML-DSA.

### Wrap keys and wraps

    W_sg = KDF(k_gs | ss_sg, "wrap-sg")      satellite and ground station
    W_gu = KDF(k_gu | ss_gu, "wrap-gu")      ground station and user

| Wrap | Content | Key | In |
|---|---|---|---|
| C_su->g | k_su, ss_us | W_sg | MSG6 |
| C_gs->u | k_gs, ss_sg | W_gu | MSG7, MSG7f |
| C_gu->s | k_gu, ss_gu | W_sg | MSG7 |

Each wrap is AES-256-GCM over 64 octets, 80 octets with the tag. The ground station sends MSG7
only after tag_u verified. This order matters and the proof uses it.

### Confirmation tags

    tag_u  = h(k_su | k_gu | ss_us | ss_gu | mu_u | mu_s | mu_g | "UE-fin")
    tag_g  = h(SK | mu_u | mu_s | mu_g | "GS-fin")
    tag_s  = h(SK | mu_u | mu_s | mu_g | "SAT-fin")
    tag_u' = h(SK | mu_u | mu_s | mu_g | "UE-fin-final")

The satellite makes tag_s when it has derived SK. It sends it to the user in MSG7f and to the
ground station together with the forwarded MSG8. The user checks tag_g and tag_s before it
sends MSG8. The ground station checks tag_u' and tag_s before it finishes.

### Message sizes (octets)

| Message | Full certificates | Certificates by reference |
|---|---|---|
| MSG1 UE to SAT | 13 266 | 5 692 |
| MSG2 SAT to GS | 26 550 | 11 402 |
| MSG3 GS to SAT | 14 252 | 6 678 |
| MSG4 SAT to UE | 25 334 | 10 186 |
| MSG5 UE to SAT | 34 | 34 |
| MSG6 SAT to GS | 114 | 114 |
| MSG7 GS to SAT | 194 | 194 |
| MSG7f SAT to UE | 146 | 146 |
| MSG8 UE to SAT | 34 | 34 |
| MSG8 as forwarded SAT to GS | 66 | 66 |
| Total | 79 990 | 34 546 |

### What each node erases

When SK is confirmed each node erases its ephemeral secret key, the session secrets, the
authentication secrets and the two wrap keys.

## Constellation phase

### Keys derived from SK

    K_gl  = KDF(SK, "ground-link")              to the feeder satellite, keys the ground station link
    K_ord = KDF(SK, "order")                    authenticates handover orders for this user
    SK_n  = KDF(SK, "next-link" | ID_Sn)        the user link key after handover to satellite Sn

SK itself never leaves the serving satellite. The user and the ground station derive the same
keys. After a handover SK_n takes the place of SK, so a session passes along any number of
satellites.

### End to end transfer between satellites

A key that goes from satellite A to satellite B is sent as

    c | wrap(KDF(ss), label | ID_A | ID_B | key) | Sig_A(label | ID_A | ID_B | c | wrap)

where (c, ss) = ML-KEM.Encaps(pk of B from its certificate) and Sig_A is ML-DSA-65. B checks
that the certificate of A has the satellite role, verifies the signature and decapsulates.
Labels: "GLINK" carries K_gl to the feeder, "USERSESS" carries the user identity and SK_n to
the next serving satellite. A relay satellite forwards the packet and cannot open it. The hop
by hop SDLS on the ISL stays as a second layer. The proof does not rely on it.

Size of one transfer: 1 088 + about 60 + 3 309, about 4.5 kB, about 20 ISL frames.

### Handover order

    HANDOVER | ID_UE | ID_S | ID_Sn | HMAC(K_ord, "HANDOVER" | ID_UE | ID_S | ID_Sn)

The serving satellite checks the MAC with the K_ord of the user named in the order. The key of
the ground link or of another user's session does not make a valid order.

### Erasure at handover

When the serving satellite has sent SK_n it erases SK, K_ord and K_gl of that user.

## Revocation

The authority signs a revocation list (issue time, revoked identities, one ML-DSA-65
signature). A node installs a list only if the signature verifies and the list is newer than
the one it holds. It then drops the cached certificate of every revoked identity.

## What is proven

See `formal/RESULTS.md` for the full table. In short:

| Property | Holds if |
|---|---|
| Secrecy of SK and injective agreement on SK for all six ordered pairs | no ML-DSA key of the three parties leaks before the handshake ends and no ephemeral key, k_gs or k_gu leaks. Every long term ML-KEM key may leak at any time |
| The same properties | no long term ML-KEM key of the three parties leaks. Every ML-DSA key, every ephemeral key and every session secret may leak at any time |
| SK is revealed only by a compromise of the serving satellite while it holds SK | always |
| K_gl and SK_n are revealed only through the sender, the destination or the destination's ML-KEM key | always |
| A satellite takes over a user only on an order of the ground station for that user and target | the ML-DSA key of the serving satellite did not leak and it was not compromised |

## Limits that remain

| Limit | Why |
|---|---|
| With both long term keys of one party the adversary takes its place | Any authentication fails when all keys of a party are known |
| The serving satellite holds SK while it serves the user | It has to protect the user link |
| A satellite whose ML-DSA key leaked can hand a neighbor a key of its choice for a user | The neighbor cannot check the ground station's order itself. A fix is an ML-DSA signature of the ground station on the order, 3.3 kB more |
| Revocation and the freshness window are not in the formal model | They are tested by experiment |

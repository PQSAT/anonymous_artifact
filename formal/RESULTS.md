# Formal verification of the PQSAT protocol with Tamarin

Tamarin 1.10.0 with Maude 3.5. Both models were run from start to end and every lemma was
verified with no wellformedness warning. The proof files are in `proofs/`.

| Model | File | Lemmas | Time |
|---|---|---|---|
| Handshake, eight messages | `pqsat_handshake.spthy` | 22 | 2 920 s |
| Constellation phase: ground link key, handover | `pqsat_handover.spthy` | 11 | 8 s |

Run with `sh run_tamarin.sh`. The design is in `protocol/PROTOCOL.md`. The two models are
verified separately. Their composition is not formally verified.

## What the adversary can do

Full control of every link, including every ISL (Dolev Yao). In addition it may reveal each of
these on its own: a long term ML-DSA key, a long term ML-KEM key, an ephemeral ML-KEM key of
one handshake, each of the session secrets k_su, k_gs and k_gu and every key held by a
compromised satellite.

## Handshake: properties that hold

Two independent sets of conditions. The properties hold if EITHER set is met.

| Set | Must not leak | May leak |
|---|---|---|
| ML-DSA and ephemeral layer | ML-DSA keys of the three parties before the handshake ends. Ephemeral keys, k_gs and k_gu | Every long term ML-KEM key at any time. Every ML-DSA key after the handshake. k_su |
| ML-KEM layer | Long term ML-KEM keys of the three parties | Every ML-DSA key at any time. Every ephemeral key. Every session secret |

| Lemma | Statement | Set | Result |
|---|---|---|---|
| executable | An honest run ends with the same SK at user, satellite and ground station | | verified, 43 steps |
| secrecy_dsa | SK stays secret (forward secrecy) | ML-DSA | verified, 310 steps |
| secrecy_kem | SK stays secret | ML-KEM | verified, 104 steps |
| agree_dsa_ue_gs | User agrees with ground station on SK, injective | ML-DSA | verified, 561 steps |
| agree_dsa_ue_sat | User agrees with satellite on SK, injective | ML-DSA | verified, 625 steps |
| agree_dsa_sat_gs | Satellite agrees with ground station on SK, injective | ML-DSA | verified, 437 steps |
| agree_dsa_sat_ue | Satellite agrees with user on SK, injective | ML-DSA | verified, 293 steps |
| agree_dsa_gs_ue | Ground station agrees with user on SK, injective | ML-DSA | verified, 189 steps |
| agree_dsa_gs_sat | Ground station agrees with satellite on SK, injective | ML-DSA | verified, 333 steps |
| agree_kem_ue_gs | User agrees with ground station on SK, injective | ML-KEM | verified, 108 steps |
| agree_kem_ue_sat | User agrees with satellite on SK, injective | ML-KEM | verified, 123 steps |
| agree_kem_sat_gs | Satellite agrees with ground station on SK, injective | ML-KEM | verified, 109 steps |
| agree_kem_sat_ue | Satellite agrees with user on SK, injective | ML-KEM | verified, 84 steps |
| agree_kem_gs_ue | Ground station agrees with user on SK, injective | ML-KEM | verified, 71 steps |
| agree_kem_gs_sat | Ground station agrees with satellite on SK, injective | ML-KEM | verified, 76 steps |

SK depends on the identities, the three nonces and the whole transcript Pi3, so agreement on
SK is agreement on all of them.

Helper lemmas: types (sources), sig_key_secret, kem_key_secret, gs_secret_kgs, gs_secret_kgu
and auth_secret. The last one is the core of the ML-KEM set: an authentication secret stays
secret as long as the long term ML-KEM keys of the three parties of its handshake do not leak.
It is proven by induction, 3 956 steps.

## Constellation phase: properties that hold

| Lemma | Statement | Result |
|---|---|---|
| executable | A ground link transfer and a handover complete, user and new satellite hold the same key | verified, 19 steps |
| sk_secret | SK is revealed only by a compromise of the serving satellite while it holds SK | verified |
| glink_secret | The ground link key is revealed only through the serving satellite, the feeder it was sent to or that feeder's ML-KEM key | verified |
| next_key_secret | The key after handover is revealed only through the old serving satellite before it erased SK, the new satellite or its ML-KEM key | verified |
| glink_authentic | The feeder accepts a ground link key only from the satellite that sent it, unless that satellite's ML-DSA key leaked | verified |
| handover_authentic | A satellite takes over a user only with the key the serving satellite sent. That satellite sent it only on an order of the ground station for that user and target | verified |

These hold with the adversary in control of every ISL, so they do not depend on the ISL keys
or on the honesty of relay satellites.

## Limits that remain, each shown by a trace

| Lemma | Limit |
|---|---|
| R0_both_keys_of_one_party | With both long term keys of the satellite (ML-DSA and ML-KEM) the adversary takes its place and learns SK. The two sets of conditions are tight |
| R1_serving_satellite_holds_sk | The serving satellite holds SK while it serves the user |
| R2_leaked_satellite_signing_key | A satellite whose ML-DSA key leaked can make a neighbor take over a user with a key the adversary chose |

## Modeling choices and limits

| Item | Choice |
|---|---|
| ML-DSA, ML-KEM, AES-GCM, SHA3, HMAC, KDF | Perfect symbolic primitives. No statement about concrete security or side channels |
| Certificates | The trusted authority is honest. Binding of identity and role to the public keys is an authentic lookup. Revocation is not modeled |
| Timestamps | Fresh values. The freshness window is not modeled and no lemma needs it or the replay cache |
| Forwarded fields | A node that forwards fields it received in clear adds nothing to the adversary's knowledge, so only new terms are put on the network |
| Mixed leaks | A leak of an ML-DSA key of one party together with an ML-KEM key of another party is outside both sets and is not covered |
| Handshake inside the constellation model | Replaced by one rule that gives a fresh SK to the three parties, which is what the handshake lemmas establish |
| Hand over | One handover per session |
| Sessions | Unbounded number of parties and sessions |

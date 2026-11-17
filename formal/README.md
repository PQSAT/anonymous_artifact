# Formal verification in Tamarin

Two models, verified separately:

| Model | File | Lemmas |
|---|---|---|
| Handshake, eight messages | `pqsat_handshake.spthy` | 22 |
| Constellation phase (ground link key transfer, handover) | `pqsat_handover.spthy` | 11 |

## Run

Needs Tamarin 1.10.0 and Maude 3.5 on the PATH (Ubuntu 22.04 or later).

    sh run_tamarin.sh

or one model at a time:

    tamarin-prover --derivcheck-timeout=0 --prove pqsat_handover.spthy
    tamarin-prover --derivcheck-timeout=0 --prove pqsat_handshake.spthy

Expected: every lemma `verified`, no wellformedness warning. The constellation model takes a
few seconds. The handshake model takes about 30 to 50 minutes on a desktop workstation and
needs about 8 GB of memory. The proofs as produced by the prover are in `proofs/`.

Five of the 33 lemmas are existence lemmas (`exists-trace`): two show that an honest run
completes and three show the limits that remain.

`RESULTS.md` lists every lemma with its assumption set and proof length.

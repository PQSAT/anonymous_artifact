#!/bin/sh
# Proves both models. Needs tamarin-prover 1.10.0 and maude 3.5 on the PATH.
# About 28 minutes for the handshake and 5 seconds for the constellation phase on two cores.
export LC_ALL=C.UTF-8
cd "$(dirname "$0")"
tamarin-prover --derivcheck-timeout=0 --prove pqsat_handshake.spthy --output=proofs/proof_handshake.spthy
tamarin-prover --derivcheck-timeout=0 --prove pqsat_handover.spthy  --output=proofs/proof_handover.spthy

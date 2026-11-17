"""Where the testbed's parts live.  Set PQSAT_PQC, PQSAT_TEST and PQSAT_GSLIB to relocate;
the defaults are the release layout (platform/ beside protocol/, versal/ and gs/) and the
development tree."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.dirname(os.path.dirname(HERE))          # release root when installed as release/platform/pqsat_testbed


def _first(*cands):
    for c in cands:
        if c and os.path.isdir(c):
            return c
    return cands[0]


PQC = _first(os.environ.get("PQSAT_PQC"), os.path.join(REL, "protocol"))
TEST = _first(os.environ.get("PQSAT_TEST"), os.path.join(REL, "flight", "apps", "sat_rf", "test"))
GSLIB = _first(os.environ.get("PQSAT_GSLIB"), os.path.join(REL, "gs", "lib"), os.path.join(TEST, "gs", "lib"))
KEYS = os.path.join(PQC, "keys")
SATSIM = os.path.join(TEST, "satsim")

for p in (GSLIB, TEST, PQC):
    if p not in sys.path:
        sys.path.insert(0, p)

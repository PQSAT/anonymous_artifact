"""pqsat_testbed: a reusable satellite constellation security testbed.

Flight code (NASA cFS satellite core with CCSDS 232.0/132.0/232.1/133.0, SDLS by NASA
CryptoLib, an inter satellite link) run either as emulated processes or on the Versal
board with LoRa radios; terminals on the real link library; a post quantum three party
authentication protocol as the reference plug in.  Other protocols, link models,
experiments and attacks plug in at four interfaces (see pqsat_testbed.plugins).

    from pqsat_testbed import Platform
    p = Platform(backend="emulator", topology="constellation")
    rec = p.run("handshake", protocol="pqsat", mode="ref", runs=1)
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("PQSAT_ROOT", os.path.dirname(HERE))

__version__ = "0.1.0"

from .platform import Platform  # noqa: E402,F401
from .schema import Database    # noqa: E402,F401

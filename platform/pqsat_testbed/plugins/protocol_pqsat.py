"""Reference protocol plug in: the post quantum three party authentication and key
establishment protocol (hybrid ML-DSA-65 with ML-KEM-768, SHA3, HKDF, AES-256-GCM),
exactly as implemented in pqsat_roles.py (user and ground) and in the flight satellite
module sat_auth.c.  The platform wraps it; it is not changed.

Options: mode "full" or "ref" (certificate mode), preload (pre cached certificates),
sdls (key SDLS from the session key at the end), timeout.
"""
from pqsat_testbed import paths  # noqa: F401  (puts pqc and the link library on the path)
from pqsat_testbed.plugins import Protocol
from handshake_runner import run_handshake, ID_SAT
from pqsat_roles import HandshakeFailed


class PqsatProtocol(Protocol):
    name = "pqsat"
    description = ("Post quantum three party authentication, hybrid ML-DSA-65 + ML-KEM-768, seven messages "
                   "plus confirmation; satellite role in the flight module")
    satellite_role = "flight"

    def run(self, platform, nodes, mode="ref", preload=True, sdls=True, timeout=1800.0, verbose=False, **_):
        ue, gs = nodes.ue, nodes.gs
        sat = nodes.serving                        # name of the user's serving satellite, "sat1" or "sat2"
        sat_id = nodes.sats[sat]["scid"]
        try:
            rec = run_handshake(ue, gs, mode=mode, preload=preload, timeout=timeout, verbose=verbose, sdls=sdls,
                                sat=sat, sat_id=sat_id)
        except HandshakeFailed as e:
            rec = dict(mode=mode, ok=False, error=str(e), seconds=None, octets_total=0, messages=[])
        rec["serving_satellite"] = f"{sat_id:#x}"
        rec["protocol"] = self.name
        return rec


class PqsatPythonSatellite(Protocol):
    """The same protocol with the satellite role in Python (pqsat_roles.SatelliteSession),
    the satellite core handing authentication messages to the harness.  For protocol
    development: a researcher's own protocol follows this shape."""
    name = "pqsat-python-sat"
    description = "Same protocol, satellite role in Python on the harness (development mode)"
    satellite_role = "python"

    def satellite_session(self, sat_name):
        from handshake_runner import load_bundle
        from pqsat_roles import SatelliteSession
        b = load_bundle(sat_name)
        s = SatelliteSession(b, 0x0001, full_certs=False)
        s.cache[0x0001] = load_bundle("gs")["cert"]
        s.cache[0x0011] = load_bundle("ue1")["cert"]
        return _Adapter(s)

    def run(self, platform, nodes, **options):
        return PqsatProtocol().run(platform, nodes, **options)


class _Adapter:
    def __init__(self, s):
        self.s = s

    ROLE = {0x0001: "gs", 0x0011: "ue", 0x0012: "ue"}
    ADDR = {"gs": 0x0001, "ue": 0x0011}

    def handle(self, src, msg):
        out = self.s.handle(msg, self.ROLE.get(src, "ue"))
        return [(self.ADDR[dst], m) for dst, m in out] if out else []

    def session_key(self):
        return getattr(self.s, "sk", None)

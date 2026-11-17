"""Add a protocol: subclass Protocol, set a name, run it on the same link.  The satellite
role runs in Python on the harness; the flight core carries the messages.

This toy protocol is one signed nonce each way and is here only to show the shape."""
import os
import time
from pqsat_testbed.plugins import Protocol
from pqsat_testbed import Platform


class EchoProtocol(Protocol):
    name = "echo"
    description = "Toy: user sends a nonce to the satellite, satellite forwards it to the ground, ground echoes"
    satellite_role = "python"

    def satellite_session(self, sat_name):
        class Sat:
            sk = None
            def handle(self, src, msg):
                return [(0x0001 if src == 0x0011 else 0x0011, msg)]   # forward to the other party
            def session_key(self):
                return None
        return Sat()

    def run(self, platform, nodes, **opts):
        sat_id = nodes.sats[nodes.serving]["scid"]
        nonce = bytes([0x7E, 0x01]) + os.urandom(30)
        t0 = time.time()
        ok = nodes.ue.send_auth(sat_id, nonce)
        got = nodes.gs.wait_auth(120)
        back = nodes.gs.send_auth(sat_id, got[1]) if got else False
        echo = nodes.ue.wait_auth(120) if back else None
        return dict(ok=bool(echo and echo[1] == nonce), seconds=round(time.time() - t0, 3), octets_total=2 * len(nonce),
                    messages=[dict(msg="nonce", direction="up", octets=len(nonce), segments=1, retransmissions=0,
                                   seconds=0)], sk_user=None, sk_ground=None)


p = Platform(db="example.db")
rid = p.run("handshake", backend="emulator", topology="single", protocol="echo", runs=1)
print(p.db.run(rid)["summary"])

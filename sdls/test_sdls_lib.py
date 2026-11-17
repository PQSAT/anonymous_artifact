"""SDLS layer checks: NASA CryptoLib with the libpqsat backend, cross checked
byte for byte against NASA CryptoLib with its default libgcrypt backend.

Frames are built with the ground library's own CCSDS encoders, so the test
uses exactly the frame formats the testbed sends.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "gs", "lib"))
from sdls import SdlsEndpoint, error_name, SDLS_TM_FRAME_LEN, SDLS_OVERHEAD  # noqa: E402
from ccsds_link import tc_frame, space_packet, crc16, parse_tm               # noqa: E402

SCID = 0x101
SK = bytes(range(32))
PQ = os.path.join(HERE, "out", "libsatsdls.so")
GC = os.path.join(HERE, "out", "libsatsdls_gcry.so")
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)


def endpoints(lib):
    u, s = SdlsEndpoint(SCID, lib, "user"), SdlsEndpoint(SCID, lib, "sat")
    u.start(SK, 1)
    s.start(SK, 0)
    return u, s


def clear_tc(ns, payload):
    pkt = space_packet(1, 600, ns, b"\x00\x11\x00\x01" + payload)
    return tc_frame(SCID, 1, ns, bytes([0xC0]) + pkt), pkt


def tm_layout(data, vcfc=0, clcw=b"\x01\x04\x00\x07"):
    """Satellite side layout for a protected TM VC1 frame, 255 octets."""
    room = SDLS_TM_FRAME_LEN - 6 - 14 - 16 - 4 - 2
    assert len(data) <= room
    data = data + b"\x07\xff" * ((room - len(data)) // 2) + b"\x00" * ((room - len(data)) % 2)  # idle fill
    hdr = bytes([(SCID >> 4) & 0x3F, ((SCID & 0xF) << 4) | (2 << 1) | 1, 0, vcfc, 0x18, 0x00])
    body = hdr + b"\x00" * 14 + data + b"\x00" * 16 + clcw
    c = crc16(body)
    return body + bytes([c >> 8, c & 0xFF])


print("--- 1. TC: user applies, satellite processes (libpqsat backend) ---")
u, s = endpoints(PQ)
f0, pkt0 = clear_tc(0, b"hello satellite, this text must not be visible on air")
e0, r = u.tc_apply(f0)
check("TC ApplySecurity succeeds", r == 0, error_name(r))
check(f"protected frame is clear frame + {SDLS_OVERHEAD} octets", e0 and len(e0) == len(f0) + SDLS_OVERHEAD,
      f"{len(f0)} -> {len(e0) if e0 else None}")
check("plaintext does not appear in the protected frame", e0 and b"must not be visible" not in e0)
check("SPI 1 follows the segment header", e0 and e0[6:8] == b"\x00\x01")
check("FECF of the protected frame is valid", e0 and crc16(e0[:-2]) == (e0[-2] << 8 | e0[-1]))
out, r = s.tc_process(e0)
check("TC ProcessSecurity succeeds", r == 0, error_name(r))
check("satellite recovers segment header and the exact space packet", out and out[0] == 0xC0 and out[1] == pkt0,
      f"{len(out[1]) if out else 0} octets")

print("--- 2. TM VC2: satellite applies, user processes (libpqsat backend) ---")
msg = space_packet(0, 600, 5, b"\x01\x01\x00\x11" + b"downlink text for the user")
tf = tm_layout(msg)
p, r = s.tm_apply(tf)
check("TM ApplySecurity succeeds", r == 0, error_name(r))
check("protected TM frame is the fixed 255 octets", p and len(p) == SDLS_TM_FRAME_LEN)
check("plaintext does not appear in the protected TM frame", p and b"downlink text" not in p)
check("SPI 2 follows the TM primary header", p and p[6:8] == b"\x00\x02")
check("TM frame still parses as CCSDS TM with OCF", p and parse_tm(p)["clcw"] is not None)
d, r = u.tm_process(p)
check("TM ProcessSecurity succeeds", r == 0, error_name(r))
check("user recovers the exact space packet", d is not None and d.startswith(msg), f"{len(d) if d else 0} octets")

print("--- 3. Cross check: libpqsat backend against NASA's libgcrypt backend ---")
up, sp = endpoints(PQ)
ug, sg = endpoints(GC)
same_tc = True
same_tm = True
for i in range(5):
    f, _ = clear_tc(i, bytes([i]) * (40 + 30 * i))
    a, ra = up.tc_apply(f)
    b, rb = ug.tc_apply(f)
    same_tc &= (ra == rb == 0 and a == b)
    out, r = sg.tc_process(a)
    same_tc &= (r == 0)
    out, r = sp.tc_process(b)
    same_tc &= (r == 0)
    t = tm_layout(space_packet(0, 600, i, bytes([0x40 + i]) * (20 + 25 * i)), vcfc=i)
    a, ra = sp.tm_apply(t)
    b, rb = sg.tm_apply(t)
    same_tm &= (ra == rb == 0 and a == b)
    d, r = ug.tm_process(a)
    same_tm &= (r == 0)
    d, r = up.tm_process(b)
    same_tm &= (r == 0)
check("TC frames from both backends are byte identical, and each verifies with the other", same_tc)
check("TM frames from both backends are byte identical, and each verifies with the other", same_tm)

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)

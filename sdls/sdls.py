"""Python access to the SAT-1 SDLS layer (NASA CryptoLib + libpqsat backend).

Each SdlsEndpoint loads its own private copy of libsatsdls.so, because CryptoLib
keeps its security association table in process globals and two terminals in
one process (user and ground, as in the testbed laptop) must not share
counters.  A copy is a separate file, so the dynamic loader gives it separate
globals.
"""
import ctypes
import os
import shutil
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_lib():
    env = os.environ.get("SATSDLS_LIB")
    name = "satsdls.dll" if os.name == "nt" else "libsatsdls.so"      # Windows build: sdls/build_sdls_windows.sh
    for c in ([env] if env else []) + [os.path.join(HERE, name), os.path.join(HERE, "out", name),
                                      os.path.join(HERE, "..", "sdls", name),
                                      os.path.join(HERE, "..", "..", "sdls", "out", name)]:
        if c and os.path.exists(c):
            return c
    raise ImportError("libsatsdls.so not found: build it with sdls/build_sdls.sh or set SATSDLS_LIB")


LIB = _find_lib()

SDLS_OVERHEAD = 30
SDLS_HDR_LEN = 14
SDLS_MAC_LEN = 16
SDLS_TM_FRAME_LEN = 255
SPI_TC, SPI_TM, SPI_TC_GS, SPI_TM_GS = 1, 2, 6, 9
VC_TC_USER, VC_TM_USER, VC_TM_GROUND = 1, 2, 4
ROLE_SATELLITE, ROLE_USER, ROLE_GROUND = 0, 1, 2

ERRORS = {0: "ok", -21: "MAC verification failed", -23: "IV outside anti-replay window (replay)",
          -13: "ARSN outside anti-replay window (replay)", -8: "no operational security association",
          -12: "invalid FECF", -56: "SPI out of range", -60: "SPI does not match", -2: "CryptoLib not initialised"}


def error_name(r):
    return ERRORS.get(r, f"CryptoLib error {r}")


class SdlsStats(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in ("tc_ok", "tc_bad_mac", "tc_replay", "tc_other",
                                               "tm_ok", "tm_bad_mac", "tm_replay", "tm_other")] + \
               [("last_error", ctypes.c_int32)]


class SdlsEndpoint:
    _count = 0

    def __init__(self, scid, lib=LIB, name="sdls"):
        SdlsEndpoint._count += 1
        d = tempfile.mkdtemp(prefix=f"satsdls_{name}_")
        path = os.path.join(d, f"libsatsdls_{SdlsEndpoint._count}" + (".dll" if os.name == "nt" else ".so"))
        shutil.copy(lib, path)
        self.L = ctypes.CDLL(path, mode=ctypes.RTLD_LOCAL)
        L = self.L
        u8p = ctypes.POINTER(ctypes.c_uint8)
        ip = ctypes.POINTER(ctypes.c_int)
        L.SatSdls_Init.argtypes = [ctypes.c_uint16]
        L.SatSdls_Start.argtypes = [ctypes.c_char_p, ctypes.c_int]
        L.SatSdls_TcApply.argtypes = [ctypes.c_char_p, ctypes.c_int, u8p, ctypes.c_int, ip]
        L.SatSdls_TcProcess.argtypes = [ctypes.c_char_p, ctypes.c_int, u8p, u8p, ctypes.c_int, ip]
        L.SatSdls_TmApply.argtypes = [u8p]
        L.SatSdls_TmProcess.argtypes = [ctypes.c_char_p, ctypes.c_int, u8p, ctypes.c_int, ip]
        L.SatSdls_GetStats.argtypes = [ctypes.POINTER(SdlsStats)]
        for f in ("SatSdls_Init", "SatSdls_Start", "SatSdls_TcApply", "SatSdls_TcProcess", "SatSdls_TmApply",
                  "SatSdls_TmProcess"):
            getattr(L, f).restype = ctypes.c_int32
        L.SatSdls_Active.restype = ctypes.c_int
        r = L.SatSdls_Init(scid)
        if r != 0:
            raise RuntimeError(f"SatSdls_Init: {error_name(r)}")

    def start(self, sk, role=1):
        """role 0: satellite; 1: user (sends TC VC1, reads TM VC2); 2: ground (sends TC VC0, reads TM VC4)."""
        r = self.L.SatSdls_Start(bytes(sk), role)
        if r != 0:
            raise RuntimeError(f"SatSdls_Start: {error_name(r)}")

    def stop(self):
        self.L.SatSdls_Stop()

    @property
    def active(self):
        return bool(self.L.SatSdls_Active())

    def tc_apply(self, frame):
        out = (ctypes.c_uint8 * 1024)()
        n = ctypes.c_int(0)
        r = self.L.SatSdls_TcApply(bytes(frame), len(frame), out, 1024, ctypes.byref(n))
        return (bytes(out[:n.value]) if r == 0 else None), r

    def tc_process(self, frame):
        seg = ctypes.c_uint8(0)
        pdu = (ctypes.c_uint8 * 1024)()
        n = ctypes.c_int(0)
        r = self.L.SatSdls_TcProcess(bytes(frame), len(frame), ctypes.byref(seg), pdu, 1024, ctypes.byref(n))
        return (seg.value, bytes(pdu[:n.value])) if r == 0 else None, r

    def tm_apply(self, frame):
        buf = (ctypes.c_uint8 * SDLS_TM_FRAME_LEN).from_buffer_copy(bytes(frame))
        r = self.L.SatSdls_TmApply(buf)
        return (bytes(buf) if r == 0 else None), r

    def tm_process(self, frame):
        out = (ctypes.c_uint8 * 2048)()
        n = ctypes.c_int(0)
        r = self.L.SatSdls_TmProcess(bytes(frame), len(frame), out, 2048, ctypes.byref(n))
        return (bytes(out[:n.value]) if r == 0 else None), r

    def stats(self):
        s = SdlsStats()
        self.L.SatSdls_GetStats(ctypes.byref(s))
        return {f: getattr(s, f) for f, _ in s._fields_}

"""Post quantum primitives for the constellation testbed.

One shared library, built from PQClean, is linked by the flight software on the
Versal and loaded here by the ground station and the user terminal.  Both ends
therefore execute byte identical cryptography, which removes a whole class of
interoperability bug from the measurements.

Primitives, as the protocol specifies them:
    ML-DSA-65   FIPS 204, NIST Category 3, signatures
    ML-KEM-768  FIPS 203, NIST Category 3, key encapsulation
    Falcon-512  carried for the size and speed comparison only
"""
import ctypes
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = ctypes.CDLL(os.environ.get("PQSAT_LIB", os.path.join(_HERE, "lib", "pqsat.dll" if os.name == "nt" else "libpqsat.so")))

_B = ctypes.c_ubyte
_SZ = ctypes.c_size_t


def _buf(n):
    return (_B * n)()


class _Sign:
    def __init__(self, prefix, pk_len, sk_len, sig_len):
        self.pk_len, self.sk_len, self.sig_len = pk_len, sk_len, sig_len
        self._keypair = getattr(_LIB, prefix + "_crypto_sign_keypair")
        self._sign = getattr(_LIB, prefix + "_crypto_sign_signature")
        self._verify = getattr(_LIB, prefix + "_crypto_sign_verify")
        self._keypair.restype = ctypes.c_int
        self._sign.restype = ctypes.c_int
        self._verify.restype = ctypes.c_int

    def keypair(self):
        pk, sk = _buf(self.pk_len), _buf(self.sk_len)
        if self._keypair(pk, sk) != 0:
            raise RuntimeError("key generation failed")
        return bytes(pk), bytes(sk)

    def sign(self, msg, sk):
        sig = _buf(self.sig_len)
        slen = _SZ(0)
        m = (_B * len(msg)).from_buffer_copy(msg)
        k = (_B * self.sk_len).from_buffer_copy(sk)
        if self._sign(sig, ctypes.byref(slen), m, _SZ(len(msg)), k) != 0:
            raise RuntimeError("signing failed")
        return bytes(sig)[:slen.value]

    def verify(self, sig, msg, pk):
        s = (_B * len(sig)).from_buffer_copy(sig)
        m = (_B * len(msg)).from_buffer_copy(msg)
        p = (_B * self.pk_len).from_buffer_copy(pk)
        return self._verify(s, _SZ(len(sig)), m, _SZ(len(msg)), p) == 0


class _Kem:
    def __init__(self, prefix, pk_len, sk_len, ct_len, ss_len=32):
        self.pk_len, self.sk_len, self.ct_len, self.ss_len = pk_len, sk_len, ct_len, ss_len
        self._keypair = getattr(_LIB, prefix + "_crypto_kem_keypair")
        self._enc = getattr(_LIB, prefix + "_crypto_kem_enc")
        self._dec = getattr(_LIB, prefix + "_crypto_kem_dec")
        for f in (self._keypair, self._enc, self._dec):
            f.restype = ctypes.c_int

    def keypair(self):
        pk, sk = _buf(self.pk_len), _buf(self.sk_len)
        if self._keypair(pk, sk) != 0:
            raise RuntimeError("key generation failed")
        return bytes(pk), bytes(sk)

    def encaps(self, pk):
        ct, ss = _buf(self.ct_len), _buf(self.ss_len)
        p = (_B * self.pk_len).from_buffer_copy(pk)
        if self._enc(ct, ss, p) != 0:
            raise RuntimeError("encapsulation failed")
        return bytes(ct), bytes(ss)

    def decaps(self, ct, sk):
        ss = _buf(self.ss_len)
        c = (_B * self.ct_len).from_buffer_copy(ct)
        k = (_B * self.sk_len).from_buffer_copy(sk)
        if self._dec(ss, c, k) != 0:
            raise RuntimeError("decapsulation failed")
        return bytes(ss)


# FIPS 204 and FIPS 203 parameter sizes
ML_DSA_65 = _Sign("PQCLEAN_MLDSA65_CLEAN", 1952, 4032, 3309)
ML_KEM_768 = _Kem("PQCLEAN_MLKEM768_CLEAN", 1184, 2400, 1088)
FALCON_512 = _Sign("PQCLEAN_FALCON512_CLEAN", 897, 1281, 752)


# ---------------- symmetric primitives, from the same library ----------------

def _cbuf(b):
    return (_B * len(b)).from_buffer_copy(b) if b else (_B * 1)()


def sha3_256(data):
    out = _buf(32)
    _LIB.pqsat_sha3_256(out, _cbuf(data), _SZ(len(data)))
    return bytes(out)


def hmac_sha3_256(key, msg):
    out = _buf(32)
    _LIB.pqsat_hmac_sha3_256(out, _cbuf(key), _SZ(len(key)), _cbuf(msg), _SZ(len(msg)))
    return bytes(out)


def kdf(x, label):
    """KDF(x, label) as the protocol writes it: HKDF-SHA3-256, no salt, info = label, 32 octets."""
    out = _buf(32)
    _LIB.pqsat_kdf(out, _cbuf(x), _SZ(len(x)), label.encode())
    return bytes(out)


def aes256gcm_encrypt(key, nonce, pt, aad=b""):
    """Return ciphertext || 16 octet tag."""
    ct = _buf(max(1, len(pt)))
    tag = _buf(16)
    _LIB.pqsat_aes256gcm_encrypt(ct, tag, _cbuf(key), _cbuf(nonce), _cbuf(aad), _SZ(len(aad)),
                                 _cbuf(pt), _SZ(len(pt)))
    return bytes(ct)[:len(pt)] + bytes(tag)


def aes256gcm_decrypt(key, nonce, ct_tag, aad=b""):
    """Return plaintext, or None when the tag does not verify."""
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    pt = _buf(max(1, len(ct)))
    r = _LIB.pqsat_aes256gcm_decrypt(pt, _cbuf(key), _cbuf(nonce), _cbuf(aad), _SZ(len(aad)),
                                     _cbuf(ct), _SZ(len(ct)), _cbuf(tag))
    return bytes(pt)[:len(ct)] if r == 0 else None

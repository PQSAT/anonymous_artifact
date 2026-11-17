"""Verify the symmetric primitives in libpqsat against independent references.

HMAC-SHA3-256 : Python hmac over hashlib.sha3_256, plus the NIST example vector
HKDF           : RFC 5869 construction built from that HMAC
AES-256-GCM    : SP 800-38D example vectors and 5000 randomised differential
                 tests against the cryptography library
"""
import ctypes
import hashlib
import hmac
import os
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
L = ctypes.CDLL(os.path.join(HERE, "lib", "libpqsat.so"))
B = ctypes.c_ubyte


def buf(b):
    return (B * len(b)).from_buffer_copy(b) if b else (B * 1)()


def c_hmac(key, msg):
    out = (B * 32)()
    L.pqsat_hmac_sha3_256(out, buf(key), ctypes.c_size_t(len(key)), buf(msg), ctypes.c_size_t(len(msg)))
    return bytes(out)


def c_hkdf(ikm, info, n, salt=b""):
    out = (B * n)()
    r = L.pqsat_hkdf_sha3_256(out, ctypes.c_size_t(n), buf(salt), ctypes.c_size_t(len(salt)),
                              buf(ikm), ctypes.c_size_t(len(ikm)), buf(info), ctypes.c_size_t(len(info)))
    assert r == 0
    return bytes(out)


def c_gcm_enc(key, nonce, aad, pt):
    ct = (B * max(1, len(pt)))()
    tag = (B * 16)()
    L.pqsat_aes256gcm_encrypt(ct, tag, buf(key), buf(nonce), buf(aad), ctypes.c_size_t(len(aad)),
                              buf(pt), ctypes.c_size_t(len(pt)))
    return bytes(ct)[:len(pt)], bytes(tag)


def c_gcm_dec(key, nonce, aad, ct, tag):
    pt = (B * max(1, len(ct)))()
    r = L.pqsat_aes256gcm_decrypt(pt, buf(key), buf(nonce), buf(aad), ctypes.c_size_t(len(aad)),
                                  buf(ct), ctypes.c_size_t(len(ct)), buf(tag))
    return (bytes(pt)[:len(ct)] if r == 0 else None)


def py_hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha3_256).digest()


def py_hkdf(ikm, info, n, salt=b""):
    salt = salt or bytes(32)
    prk = py_hmac(salt, ikm)
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = py_hmac(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:n]


fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails += 1


# ---- HMAC-SHA3-256: NIST example "Sample message for keylen<blocklen" ----
key = bytes(range(32))
msg = b"Sample message for keylen<blocklen"
nist = bytes.fromhex("4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205")
check("HMAC-SHA3-256 NIST example vector", c_hmac(key, msg) == nist)
check("HMAC-SHA3-256 matches Python reference on the same input", c_hmac(key, msg) == py_hmac(key, msg))
ok = True
for _ in range(2000):
    k = secrets.token_bytes(secrets.randbelow(200))
    m = secrets.token_bytes(secrets.randbelow(600))
    ok &= c_hmac(k, m) == py_hmac(k, m)
check("HMAC-SHA3-256 2000 random key and message lengths", ok)

# ---- HKDF ----
ok = True
for _ in range(500):
    ikm = secrets.token_bytes(32 + secrets.randbelow(96))
    info = secrets.token_bytes(secrets.randbelow(64))
    n = 1 + secrets.randbelow(200)
    ok &= c_hkdf(ikm, info, n) == py_hkdf(ikm, info, n)
check("HKDF-SHA3-256 500 random cases, no salt", ok)
check("KDF label form, 32 octets", c_hkdf(b"x" * 32, b"HSig-MAC", 32) == py_hkdf(b"x" * 32, b"HSig-MAC", 32))

# ---- AES-256-GCM: SP 800-38D test case 14 (zero key, zero IV, empty) and 15/16 ----
k0 = bytes(32)
iv0 = bytes(12)
ct, tag = c_gcm_enc(k0, iv0, b"", b"")
check("GCM-256 test case 14 tag", tag == bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"))
ct, tag = c_gcm_enc(k0, iv0, b"", bytes(16))
check("GCM-256 test case 15 ciphertext", ct == bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"))
check("GCM-256 test case 15 tag", tag == bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"))

k16 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
iv16 = bytes.fromhex("cafebabefacedbaddecaf888")
pt16 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
aad16 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
ct, tag = c_gcm_enc(k16, iv16, aad16, pt16)
check("GCM-256 test case 16 ciphertext",
      ct == bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                          "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"))
check("GCM-256 test case 16 tag", tag == bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b"))

# ---- differential against cryptography, both directions, both lengths ----
ok = True
for i in range(5000):
    k = secrets.token_bytes(32)
    n = secrets.token_bytes(12)
    a = secrets.token_bytes(secrets.randbelow(48))
    p = secrets.token_bytes(secrets.randbelow(100))
    ref = AESGCM(k).encrypt(n, p, a)
    ct, tag = c_gcm_enc(k, n, a, p)
    ok &= (ct + tag == ref)
    ok &= c_gcm_dec(k, n, a, ct, tag) == p
check("GCM-256 5000 differential encrypt and decrypt against cryptography", ok)

# ---- tamper rejection and the protocol's exact wrap shape ----
k, n, a = secrets.token_bytes(32), secrets.token_bytes(12), b""
ss = secrets.token_bytes(32)
ct, tag = c_gcm_enc(k, n, a, ss)
check("wrap of a 32 octet secret is 48 octets", len(ct) + len(tag) == 48)
bad = bytearray(tag); bad[3] ^= 1
check("flipped tag bit rejected", c_gcm_dec(k, n, a, ct, bytes(bad)) is None)
bad = bytearray(ct); bad[0] ^= 1
check("flipped ciphertext bit rejected", c_gcm_dec(k, n, a, bytes(bad), tag) is None)
check("wrong nonce rejected", c_gcm_dec(k, secrets.token_bytes(12), a, ct, tag) is None)

print(f"\n{'ALL PASSED' if fails == 0 else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)

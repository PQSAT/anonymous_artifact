# SDLS layer keyed by the post quantum handshake

The SDLS layer uses the third party library CryptoLib, an implementation of CCSDS 355.0
(Space Data Link Security). It is used unmodified, from https://github.com/nasa/CryptoLib at commit
dbcb115ec5f804fef8c28b53e9978a6ada1f3a56 (14 October 2026), which build_sdls.sh
expects in ./CryptoLib (git clone, then git checkout dbcb115).

What this directory adds, through CryptoLib's own extension points:
- cryptolib_pqsat/: a cryptography backend (CryptoLib option CRYPTO_CUSTOM) that
  provides AES-256-GCM from libpqsat, so the satellite and the ground use the
  same cipher code as the handshake's wraps. Frames produced through this
  backend are byte identical to those produced through CryptoLib's default
  libgcrypt backend (test_sdls_lib.py, cross check).
- sat_sdls/: the testbed's configuration of CryptoLib (security associations,
  managed parameters) and thin wrappers over its public API. Keys and IV salts
  are derived from the handshake session key SK with the protocol's KDF.
- sdls.py: Python access for the ground and user terminals.

Security associations
  SPI 1  TC VC1  user to satellite          AES-256-GCM, 12 octet IV, 16 octet MAC
  SPI 6  TC VC0  ground station to satellite  same
  SPI 2  TM VC2  satellite to both terminals  same, fixed 255 octet frames
TM VC1 stays the clear relay channel used before the first handshake completes.
BC control frames of COP-1 (Unlock, Set V(R)) are not protected, as in the standard.

Build: sh build_sdls.sh (x86, shared library for the laptops);
CC=aarch64-linux-gnu-gcc OUT=out-aarch64 KIND=archive sh build_sdls.sh (Versal).
Test: python3 test_sdls_lib.py (needs the libgcrypt build too: BACKEND=gcry sh build_sdls.sh).

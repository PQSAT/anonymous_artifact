#!/bin/sh
# Build the two Windows libraries from the same sources as the Linux ones, on Linux, with zig
# (pip install ziglang).  Needs PQClean (PQCLEAN=path) and CryptoLib at the commit named in README.md.
#   pqsat.dll    PQClean ML-DSA-65, ML-KEM-768, Falcon-512 + pqsat_kdf.c + pqsat_gcm.c   -> protocol/lib
#   satsdls.dll  CryptoLib + the pqsat backend + sat_sdls.c, self contained              -> gs/lib, sdls
set -e
HERE=$(cd "$(dirname "$0")" && pwd); P=$HERE/../protocol; PQ=${PQCLEAN:-$P/PQClean}; CL=$HERE/CryptoLib
ZCC="python3 -m ziglang cc -target x86_64-windows-gnu -O2 -shared"
COMMON="$PQ/common/fips202.c $PQ/common/randombytes.c $PQ/common/aes.c $PQ/common/sha2.c $PQ/common/sp800-185.c $P/src/pqsat_kdf.c $P/src/pqsat_gcm.c"
$ZCC -I$P/src -I$PQ/common -I$PQ/crypto_sign/ml-dsa-65/clean -I$PQ/crypto_kem/ml-kem-768/clean -I$PQ/crypto_sign/falcon-512/clean \
    $COMMON $PQ/crypto_sign/ml-dsa-65/clean/*.c $PQ/crypto_kem/ml-kem-768/clean/*.c $PQ/crypto_sign/falcon-512/clean/*.c \
    -o $P/lib/pqsat.dll -ladvapi32
SRC="$CL/src/core/crypto.c $CL/src/core/crypto_aos.c $CL/src/core/crypto_config.c $CL/src/core/crypto_error.c
     $CL/src/core/crypto_key_mgmt.c $CL/src/core/crypto_mc.c $CL/src/core/crypto_print.c $CL/src/core/crypto_tc.c
     $CL/src/core/crypto_tm.c $CL/src/core/crypto_user.c
     $CL/src/crypto/kmc_stub/cryptography_interface_kmc.stub.c
     $CL/src/crypto/wolfssl_stub/cryptography_interface_wolfssl.stub.c
     $CL/src/key/custom_stub/key_interface_custom_stub.template.c
     $CL/src/key/internal/key_interface_internal.template.c
     $CL/src/key/kmc_stub/key_interface_kmc_stub.template.c
     $CL/src/mc/custom_stub/mc_interface_custom_stub.template.c
     $CL/src/mc/disabled/mc_interface_disabled.template.c
     $CL/src/mc/internal_stub/mc_interface_internal_stub.template.c
     $CL/src/sa/custom_stub/sa_interface_custom.stub.c
     $CL/src/sa/internal/sa_interface_inmemory.template.c
     $CL/src/sa/mariadb_stub/sa_interface_mariadb.stub.c
     $HERE/sat_sdls/sat_sdls.c
     $CL/src/crypto/libgcrypt_stub/cryptography_interface_libgcrypt.stub.c
     $HERE/cryptolib_pqsat/cryptography_interface_pqsat.c"
$ZCC -DMC_LOG_PATH=\"log.txt\" -I$CL/include -I$P/src -I$HERE/sat_sdls -I$PQ/common $SRC $COMMON -o $HERE/satsdls.dll -ladvapi32 -lws2_32
cp $HERE/satsdls.dll $HERE/../gs/lib/; rm -f $P/lib/*.lib $P/lib/*.pdb $HERE/*.lib $HERE/*.pdb
echo "built protocol/lib/pqsat.dll, sdls/satsdls.dll, gs/lib/satsdls.dll"

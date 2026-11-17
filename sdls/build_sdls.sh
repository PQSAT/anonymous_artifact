#!/bin/sh
# Build the SDLS layer: NASA CryptoLib sources (unmodified, the same set its CMake
# selects for KEY_INTERNAL SA_INTERNAL MC_DISABLED CRYPTO_CUSTOM) + the libpqsat
# backend + the SAT-1 wrapper, as one shared library (ground, Python) or one
# object archive (satellite, linked into sat_rf.so).
#   sh build_sdls.sh                   x86 shared library   out/libsatsdls.so
#   BACKEND=gcry sh build_sdls.sh      x86, NASA's libgcrypt backend, for cross checking
#   CC=aarch64-linux-gnu-gcc OUT=out-aarch64 KIND=archive sh build_sdls.sh
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
CL=$HERE/CryptoLib
PQ=${PQ:-$HERE/../protocol}
CC=${CC:-gcc}
OUT=${OUT:-$HERE/out}
KIND=${KIND:-shared}
BACKEND=${BACKEND:-pqsat}
mkdir -p "$OUT/obj-$BACKEND"
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
     $HERE/sat_sdls/sat_sdls.c"
if [ "$BACKEND" = gcry ]; then
    SRC="$SRC $CL/src/crypto/libgcrypt/cryptography_interface_libgcrypt.template.c $CL/src/crypto/custom_stub/cryptography_interface_custom_stub.template.c"
    DEF="-DSAT_SDLS_LIBGCRYPT"; LIBS="-lgcrypt"
else
    SRC="$SRC $CL/src/crypto/libgcrypt_stub/cryptography_interface_libgcrypt.stub.c $HERE/cryptolib_pqsat/cryptography_interface_pqsat.c"
    DEF=""; LIBS=""
fi
CFLAGS="-O2 -fPIC -Wall -Wextra -DMC_LOG_PATH=\"log.txt\" $DEF -I$CL/include -I$PQ/src -I$HERE/sat_sdls"
OBJS=""
for f in $SRC; do
    o="$OUT/obj-$BACKEND/$(basename "$f" .c).o"
    $CC $CFLAGS -c "$f" -o "$o"
    OBJS="$OBJS $o"
done
if [ "$KIND" = archive ]; then
    ${AR:-ar} rcs "$OUT/libsatsdls.a" $OBJS
    echo "built $OUT/libsatsdls.a"
else
    NAME=libsatsdls.so; [ "$BACKEND" = gcry ] && NAME=libsatsdls_gcry.so
    $CC -shared -o "$OUT/$NAME" $OBJS -L$PQ/lib -Wl,--no-as-needed -lpqsat $LIBS -Wl,-rpath,$PQ/lib
    echo "built $OUT/$NAME"
fi

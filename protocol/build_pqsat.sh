#!/bin/sh
# Build one shared library carrying every primitive the protocol needs.
# The same library is linked by the flight software and loaded by the Python
# ground software, so both ends run byte identical cryptography.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
P=${PQCLEAN:-$HERE/PQClean}
OUT=${OUT:-$HERE/lib}
CC=${CC:-gcc}
CFLAGS=${CFLAGS:--O3 -fPIC -Wall -Wextra}
SONAME=${SONAME:-libpqsat.so}
mkdir -p "$OUT"
SRC="$P/common/fips202.c $P/common/randombytes.c $P/common/aes.c $P/common/sha2.c $P/common/sp800-185.c"
SRC="$SRC $(ls $P/crypto_sign/ml-dsa-65/clean/*.c)"
SRC="$SRC $(ls $P/crypto_kem/ml-kem-768/clean/*.c)"
SRC="$SRC $(ls $P/crypto_sign/falcon-512/clean/*.c)"
SRC="$SRC $HERE/src/pqsat_kdf.c $HERE/src/pqsat_gcm.c"
$CC $CFLAGS -shared -Wl,-soname,$SONAME -o "$OUT/$SONAME" $SRC \
    -I"$HERE/src" -I"$P/common" \
    -I"$P/crypto_sign/ml-dsa-65/clean" \
    -I"$P/crypto_kem/ml-kem-768/clean" \
    -I"$P/crypto_sign/falcon-512/clean"
echo "built $OUT/$SONAME"

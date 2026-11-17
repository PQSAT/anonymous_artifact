#!/bin/sh
# Build the emulated satellite: the flight core and auth module, the SDLS layer
# (sdls/, see its README), linked against libpqsat.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
S=${S:-$HERE/../fsw/src}
SD=${SD:-$HERE/../../../../sdls}
PQ=${PQ:-$HERE/../../../../protocol}
[ -f $SD/out/libsatsdls.so ] || (cd $SD && sh build_sdls.sh)
gcc -O2 -Wall -o ${OUT:-satsim} satsim_c.c $S/sat_ccsds.c $S/sat_auth.c -I$S -I$SD/sat_sdls -I$PQ/src \
    -L$SD/out -lsatsdls -L$PQ/lib -lpqsat -Wl,-rpath,$SD/out -Wl,-rpath,$PQ/lib -lm
# the same satellite without the certificate policy, for the comparison in test_cert_substitution.py
gcc -O2 -Wall -DAUTH_NO_CERT_PIN -o satsim_nopin satsim_c.c $S/sat_ccsds.c $S/sat_auth.c -I$S -I$SD/sat_sdls -I$PQ/src \
    -L$SD/out -lsatsdls -L$PQ/lib -lpqsat -Wl,-rpath,$SD/out -Wl,-rpath,$PQ/lib -lm
echo "built satsim and satsim_nopin"

#!/bin/sh
# Build authsim: the satellite side of the handshake (the flight authentication module,
# sat_auth.c) as a line process, for test_interop.py and test_attacks_protocol.py.
# Needs lib/libpqsat.so (sh build_pqsat.sh).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
S=$HERE/../flight/apps/sat_rf/fsw/src
gcc -O2 -Wall -o "$HERE/authsim" "$HERE/src/authsim.c" "$S/sat_auth.c" -I"$S" -I"$HERE/src" \
    -L"$HERE/lib" -lpqsat -Wl,-rpath,"$HERE/lib" -lm
echo "built authsim"

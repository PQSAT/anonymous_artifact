#!/bin/sh
# Ground laptop (Linux) check, run once before the first over the air handshake:
#     cd gs && sh preflight.sh
# Checks Python, pyserial, the PQ library, the keys, the protocol self tests and
# the two radios. Prints PASS or the exact thing to fix.
cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)
fail() { echo "FAIL: $*"; exit 1; }

command -v python3 >/dev/null || fail "python3 missing: sudo apt install python3"
python3 -c "import serial" 2>/dev/null || fail "pyserial missing: pip3 install --user pyserial  (or sudo apt install python3-serial)"
echo "ok   python3 and pyserial"

[ -f "$ROOT/protocol/lib/libpqsat.so" ] || fail "protocol/lib/libpqsat.so missing, unzip the release again"
python3 -c "import sys; sys.path.insert(0,'$ROOT/protocol'); import pqsat" 2>/dev/null \
    || fail "libpqsat.so does not load on this laptop: cd $ROOT/protocol && git clone https://github.com/PQClean/PQClean && sh build_pqsat.sh"
echo "ok   PQ library loads"

for k in ue1.pickle gs.pickle sat1.pickle gs.cert ue1.cert sat1.bundle; do
    [ -f "$ROOT/protocol/keys/$k" ] || fail "key file protocol/keys/$k missing"
done
echo "ok   keys present"

echo "...  protocol self tests (about 30 s)"
(cd "$ROOT/protocol" && python3 test_symmetric.py >/tmp/pf1.txt 2>&1) || { tail -5 /tmp/pf1.txt; fail "test_symmetric.py"; }
(cd "$ROOT/protocol" && python3 test_handshake.py >/tmp/pf2.txt 2>&1) || { tail -5 /tmp/pf2.txt; fail "test_handshake.py"; }
echo "ok   protocol self tests ALL PASSED"

for p in /dev/ttyACM0 /dev/ttyACM1; do
    [ -e $p ] || fail "$p not present: plug in both T-Beams, then ls /dev/ttyACM*"
    [ -r $p ] && [ -w $p ] || fail "$p not accessible: sudo chmod a+rw /dev/ttyACM*"
done
echo "ok   radios /dev/ttyACM0 (ground) and /dev/ttyACM1 (user)"
echo "PREFLIGHT PASS"

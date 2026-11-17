#!/bin/sh
# Enrollment for the test constellation: the authority, three satellites, one ground station,
# one user and the pairwise inter satellite keys.  Writes protocol/keys/.  The keys are test
# keys made on your machine.  Never publish a keys folder that is used on real hardware.
set -e
cd "$(dirname "$0")"
python3 enrol.py --out keys
python3 enrol.py --out keys --add-sat sat2:0x0102
python3 enrol.py --out keys --add-sat sat3:0x0103
python3 enrol.py --out keys --isl sat1:sat2
python3 enrol.py --out keys --isl sat2:sat3
echo "keys written to protocol/keys"

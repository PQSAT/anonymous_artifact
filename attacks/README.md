# Attack scenarios

The twelve attack classes of the testbed, in one folder with one runner. Each class is shown
succeeding against the unprotected baseline and failing against the protected system inside
its test. `run_attacks.py` runs every class that needs no bench and writes a report.

```
python run_attacks.py            run the classes that run on the laptop (no radio)
python run_attacks.py --list     the catalogue and the route for each class
python run_attacks.py --only 4 5 run only these class numbers
```

It writes `attacks_report.json` and `attacks_report.csv`. The catalogue in code is
`../platform/pqsat_testbed/attacks12.py`.

## The twelve classes

| # | Class | What it shows (protected system) | Where it runs |
|---|---|---|---|
| 1 | replay_handshake | a captured MSG1 sent again is refused by the freshness check | emulator `test_attacks.py` A1 |
| 2 | forged_message | a forged MSG3 with valid framing fails the signature | emulator `test_attacks.py` A2 |
| 3 | bit_flip | a bit flipped in flight is caught by the SDLS tag and the signature | emulator `test_attacks.py` A3 |
| 4 | mitm_relay | the relay role carries frames but learns no session key | protocol `test_attacks_protocol.py` B1 |
| 5 | downgrade | a handshake relabelled to an older version is rejected | protocol B2 |
| 6 | reassembly_hold | a held first segment is freed by the timer, one buffer per channel | emulator `test_reassembly_hold.py` (+ bench) |
| 7 | window_vs_segments | a replayed inter satellite frame is dropped by the anti replay window | emulator `test_isl_attacks.py` I1 |
| 8 | airtime_exhaustion | junk MSG1 on the slow link wastes air time but authenticates nothing | emulator `test_attacks.py` A4 (+ bench) |
| 9 | replayed_handover | a recorded hand over transfer sent again is refused as a replay | emulator `test_isl_key_compromise.py` K3 |
| 10 | revocation_suppression | a suppressed or forged revocation list changes nothing; a revoked id is refused | protocol B4 |
| 11 | compromised_isl_key | one pairwise key reads its link but yields no session key and stays on its hop | emulator `test_isl_key_compromise.py` |
| 12 | session_state_corruption | forward secrecy holds; leaked long term keys open no past session | protocol B3 |

## On the air

Two classes also have an over the air form that needs a spare radio as the adversary (a fifth
board on `COMx`). The software and emulator evidence above runs on the laptop; these add the
frames on the real link. Run them with the constellation up and the bridge running.

Record the user's uplink, then send it again as is and with a bit flipped:

```
python ..\gs\adversary.py --port COMx record --seconds 120
python ..\gs\adversary.py --port COMx replay
python ..\gs\adversary.py --port COMx replay --flip
```

Read the bridge window for the satellite's reaction (the lines with rejected, replay or timed
out). Replay feeds classes 1 and 9 on the air, the bit flip feeds classes 2 and 3, and a long
record then replay against a busy link feeds class 8 (air time). Class 6 (reassembly hold) on
the air is a first segment never finished; the emulator form in `test_reassembly_hold.py` is
the measured evidence.

## What each test needs

The runner sets the environment it needs (`SAT_AUTH_DIR`, reference mode). The emulator tests
build their satellite from the flight C source once; the first run compiles it. Keys come from
`../protocol/keys`. No network, no radio, no board.

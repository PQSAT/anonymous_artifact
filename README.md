# PQSAT

Artifact of the paper "PQSAT: Evaluating Post-Quantum Security on Real Satellite Constellation
Links". It holds the authentication protocol, our own flight software that runs it, the platform,
the formal models and the recorded runs behind the tables of the paper.

Everything that needs only software runs on one Linux machine with the emulator: the flight
core is compiled as a process and talks to the real terminal library over an emulated radio
channel. The hardware results need the board and the radios and are provided as recorded runs.

## Layout

| Folder | Content |
|---|---|
| `protocol/` | The authentication protocol: specification (`PROTOCOL.md`), reference implementation of the three roles, enrollment tool, protocol tests |
| `flight/` | Our own flight software of the satellite: CCSDS link core, authentication module, application wrapper, and the emulator with its tests (`flight/apps/sat_rf/test`) |
| `sdls/` | Link security layer: configuration and cryptography backend for the SDLS library (see `sdls/README.md`) |
| `gs/` | Ground station and user terminals, handshake campaigns, handover, revocation, hardware experiment scripts |
| `bridge/` | Bridge between the board and the radios |
| `firmware/` | Firmware of the LoRa radios (868 MHz links and 433 MHz inter satellite link) |
| `board/` | Start scripts used on the board |
| `platform/` | The PQSAT platform: orbit layer, orchestrator, registry, open API, dashboard, link budget |
| `formal/` | Tamarin models, proofs and results |
| `attacks/` | The twelve attack classes and the adversary radio tool (`attacks/onair`) |
| `results/` | Recorded runs: hardware, emulation and platform database, with `summarize.py` |

The platform and the protocol are separate. The platform loads the protocol as a plug in
(`platform/pqsat_testbed/plugins/protocol_pqsat.py`) and other protocols can be added the same
way (`platform/examples/02_my_protocol.py`).

## Requirements

Ubuntu 22.04 or later, `gcc`, `git`, Python 3.10 or later. For the radios: `pip install pyserial`.
For the formal models: Tamarin 1.10.0 and Maude 3.5.

Third party code, fetched by the steps below and not included here:

- PQClean (ML-DSA-65, ML-KEM-768): https://github.com/PQClean/PQClean
- CryptoLib (CCSDS 355.0 SDLS library), commit `dbcb115ec5f804fef8c28b53e9978a6ada1f3a56`:
  https://github.com/nasa/CryptoLib
- The board build of the flight application uses the cFS framework and a cross compiler
  (`flight/sat1_defs`, `flight/toolchain`). The emulator does not need them.

## 1. Read the paper numbers from the recorded runs

    python3 results/summarize.py

Prints the handshake, handover, computation, certificate, restart and pass numbers from the
files in `results/`. No build is needed.

| Paper | Source in `results/` |
|---|---|
| Handshake on the hardware, one and two satellites, clear and under SDLS, full certificates | `hardware/auth_hw_ref_20261116_122510.json`, `auth_hw_const_ref_20261116_153434.json`, `auth_hw_const_ref_20261116_230538.json`, `auth_hw_const_full_20261116_193723.json` |
| Handover (64.4 s against 507.6 s) and ground link keying (41.4 s) | `hardware/handover_hw_ref_20261116_175631.json` |
| Computation at the satellite (18 handshakes, 5.16 ms and 11.09 ms) | satellite log lines in `hardware/logs/sat1_bridge_log*.csv.gz` |
| One pass at the bench radio setting | `hardware/auth_hw_const_orbit_ref_20261116_*.json` |
| One pass at spreading factor 7 with 22 dBm in the link model (the completed handshakes, 289.7 s and 281.2 s) | `hardware/auth_hw_const_orbit_ref_20261117_152951.json`, `auth_hw_const_orbit_ref_20261117_161240.json` |
| Certificate substitution with and without the certificate rule | `hardware/cert_substitution_hw_*.json` and the satellite log |
| Restart of the inter satellite association | `hardware/isl_restart_hw_20261117.txt` and the bridge logs |
| Physical radio attacks | `attacks/onair/onair_report.json`, `attacks/onair/onair_capture.json` |
| Emulation rows, two consecutive handovers, attack classes | `emulation/*.out`, `emulation/*.json` |

The logs in `results/hardware/logs` hold every frame sent and received by the terminals and
the bridge and every log line of the two satellites during the campaigns of 16 and 17
November 2026. Runs that failed are kept in these logs. The two result files for spreading factor 7 list the
completed handshakes.

## 2. Build

    cd protocol
    git clone --depth 1 https://github.com/PQClean/PQClean
    sh build_pqsat.sh              # lib/libpqsat.so
    sh make_keys.sh                # test keys in protocol/keys
    sh build_authsim.sh            # satellite role as a process, for the protocol tests
    cd ../sdls
    git clone https://github.com/nasa/CryptoLib && (cd CryptoLib && git checkout dbcb115ec5f804fef8c28b53e9978a6ada1f3a56)
    sh build_sdls.sh               # out/libsatsdls.so
    cd ../flight/apps/sat_rf/test
    sh build_satsim.sh             # the emulated satellite

The keys made by `make_keys.sh` are test keys for your machine. The keys of the bench are not
in this repository.

## 3. Protocol tests

    cd protocol
    python3 test_handshake.py            # the three roles, both certificate modes
    python3 test_interop.py              # Python terminals against the flight module, octet for octet
    python3 test_attacks_protocol.py     # protocol level attacks

## 4. Emulator experiments

Run from `flight/apps/sat_rf/test`. The emulated channel has the air time of the radios, so the
times are real time.

| Command | What it reproduces |
|---|---|
| `python3 test_auth_link.py` | Handshake through one satellite |
| `python3 test_constellation.py` | Two satellites over the ISL |
| `python3 test_chain.py` | Chain of three satellites, handover |
| `python3 test_two_handovers.py` | Two consecutive handovers of one session |
| `python3 test_attacks.py` | Attack classes on messages and frames |
| `python3 test_isl_attacks.py`, `python3 test_isl_key_compromise.py` | Adversary on the ISL, compromised ISL key |
| `python3 test_reassembly_hold.py` | Reassembly hold |
| `python3 test_orbit_link.py` | Handshake under the modeled pass |
| `python3 test_cert_substitution.py` | Certificate substitution with and without the certificate rule |
| `RESTARTS=5 FRAMES=10 python3 test_isl_restart.py` | Restart of the ISL association with the same key and with a new key |
| `SF=7 PTX=22 RUNS=3 python3 test_pass_rate.py` | Handshake inside one pass at spreading factor 7 |

Each test prints PASS or FAIL per check and ends with the count. The recorded outputs of these
tests are in `results/emulation`. `attacks/run_attacks.py` runs the attack classes that need no
radio and writes one report.

## 5. Platform

    pip install -e platform
    pqsat-testbed --db testbed.db --port 8080 --import-dir results/hardware

then open http://localhost:8080/ for the dashboard. The open API is described in
`platform/README.md`. `results/platform/testbed_hw.db` is the database of the hardware runs.
The site name of the ground station is masked for review.

## 6. Formal verification

    cd formal
    sh run_tamarin.sh

33 lemmas, 22 for the handshake and 11 for the constellation phase. See `formal/README.md`
and `formal/RESULTS.md`.

## 7. Hardware

The bench has one AMD Versal VC1902 board that runs two flight instances (SAT-1 and SAT-2),
four 868 MHz radios (user, ground station and one per satellite) and four 433 MHz radios for
the inter satellite link, all LILYGO T-Beam boards with the firmware in `firmware/`.

    python sat_bridge.py --versal COM7 --radio COM6 --radio2 COM5 --isl1-tx COM9 --isl1-rx COM12 --isl2-tx COM14 --isl2-rx COM15      (in bridge/)
    python auth_campaign.py --gs COM4 --ue COM8 --constellation --mode ref --runs 5      (in gs/)
    python run_handover.py --help
    python send_crl.py --help
    python cert_substitution_hw.py --gs COM4 --ue COM8
    python isl_restart_hw.py record --gs COM4

The port names are those of the bench and differ on another machine (`sat_bridge.py --list`).

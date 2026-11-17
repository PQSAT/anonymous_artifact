# pqsat testbed

A satellite constellation security testbed that other researchers can reuse. The
satellites run our own flight software (CCSDS 232.0 telecommand, 132.0 telemetry,
232.1 COP-1, 133.0 packets, SDLS 355.0, an inter satellite link); the terminals are the real link library; the channel is either an
emulated LoRa link with the half duplex behaviour measured on the hardware, or the Versal
board and T-Beam radios in the laboratory. The reference protocol is a post quantum three
party authentication and key establishment (hybrid ML-DSA-65 + ML-KEM-768) whose session
key keys SDLS on every link, including the ISL hand over to the feeder satellite.

## Run it

    pip install -e platform            # from the repository root
    pqsat-testbed --db testbed.db --port 8080 --import-dir results/hardware
    open http://localhost:8080/

or, from the repository root, `docker build -t pqsat-testbed -f platform/Dockerfile . && docker run -p 8080:8080 pqsat-testbed`.

From Python:

    from pqsat_testbed import Platform
    p = Platform(db="testbed.db")
    rid = p.run("handshake", backend="emulator", topology="constellation", protocol="pqsat", mode="ref", runs=3)
    print(p.db.run(rid)["summary"])

## Plug in

Four interfaces in `pqsat_testbed/plugins/__init__.py`: Protocol, LinkModel, Experiment,
Attack. Subclass, set `name`, drop the module in the package. Examples: `protocol_pqsat.py`
(the reference, satellite role in the flight module), `protocol_classical.py` (ECDH and
ECDSA baseline, satellite role in Python on the harness), `links.py`, `attacks.py`,
`experiments/*.py`.

## Records

One SQLite file, tables runs, handshakes, messages, frames, samples, events; the same
schema for emulation and hardware. Export any table as CSV from `/api/dataset/<table>.csv`.
Metrics per run: goodput, per link throughput, link RTT per segment (COP-1), application
RTT, one way latency, channel bit rate and utilisation, RSSI and SNR, ISL frames, SDLS
counters, satellite crypto time.

## Reproduce

Every run stores its configuration, the platform version and the satellite logs;
`POST /api/runs/{id}/replay` reruns it on the emulator.

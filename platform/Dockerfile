# Emulator backend of the testbed in one image: the flight satellite core, NASA CryptoLib,
# libpqsat (PQClean ML-DSA-65, ML-KEM-768), the terminal library, the API and the GUI.
#   docker build -t pqsat-testbed -f platform/Dockerfile .      (from the repository root)
#   docker run -p 8080:8080 pqsat-testbed
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev git && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/release
COPY . /opt/release
RUN pip install --no-cache-dir -e platform
# compiled parts: the PQ library, CryptoLib with the testbed backend, the emulated satellite
RUN cd protocol && (test -d PQClean || git clone --depth 1 https://github.com/PQClean/PQClean) && sh build_pqsat.sh && sh make_keys.sh
RUN cd sdls && (test -d CryptoLib || git clone https://github.com/nasa/CryptoLib && cd CryptoLib && git checkout dbcb115ec5f804fef8c28b53e9978a6ada1f3a56) && sh build_sdls.sh
RUN cd flight/apps/sat_rf/test && S=/opt/release/flight/apps/sat_rf/fsw/src SD=/opt/release/sdls PQ=/opt/release/protocol sh build_satsim.sh
ENV PQSAT_PQC=/opt/release/protocol PQSAT_TEST=/opt/release/flight/apps/sat_rf/test PQSAT_GSLIB=/opt/release/gs/lib
EXPOSE 8080
CMD ["pqsat-testbed", "--db", "/data/testbed.db", "--port", "8080"]

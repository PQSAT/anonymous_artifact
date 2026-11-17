"""Node registry: satellites, ground stations and users become part of the system through
one process, driven from the dashboard, without touching code.

Lifecycle of a node
    enrolled     the authority issued its certificate; keys exist in the key store
    provisioned  its provisioning bundle (the files the flight software or terminal loads)
                 and its ISL pairwise keys with every neighbour are written
    deployed     the bundle is installed where it runs (emulator key dir, SD card bundle
                 for a Versal instance, terminal key dir)
    active       the platform has heard the node (housekeeping or a terminal attach)
    revoked      certificate on the revocation list; keys retired; neighbours rekeyed

What adding a satellite does (Registry.add_satellite)
    1. allocates the SCID, plane and slot (or takes the ones given), checks the radio
       channel pair against the others and the duty cycle band;
    2. enrols it with the trusted authority (protocol/enrol.py machinery: ML-DSA-65 and
       ML-KEM-768 key pairs, certificate with the authority's hybrid signature);
    3. writes <name>.bundle (flight layout), <name>.cert and <name>.pickle in the key store;
    4. derives a pairwise ISL key with every neighbour given (or those the ring implies)
       and writes isl_<a>_<b>.key; the neighbours' environments are updated;
    5. adds the record to the constellation manifest and the database;
    6. for an emulator node, writes the satsim environment file the orchestrator uses; for
       a board, produces sd_<name>.tgz with cpuN/auth and the service unit.
Adding a user does the same for a terminal (certificate, pickle for the terminal library,
peer certificates to preload, radio port, serving policy).  Revoking a node writes the
revocation list (crl.json, signed by the authority), retires its keys and rekeys the ISLs
of its neighbours.

The registry is independent of the running platform: it reads and writes the key store,
the manifests and the database.  The API layer (api_ext.py) exposes it and the dashboard's
Nodes page drives it.
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import sqlite3
import struct
import tarfile
import time
from typing import Dict, List, Optional

from . import orbit

HERE = os.path.dirname(os.path.abspath(__file__))
REL = os.path.dirname(os.path.dirname(HERE))
KEYS = os.environ.get("PQSAT_KEYS", os.path.join(REL, "protocol", "keys"))
PQC = os.environ.get("PQSAT_PQC", os.path.join(REL, "protocol"))

ID_GS_DEFAULT = 0x0001
VALID_SCID = range(0x101, 0x1FF)
VALID_USER = range(0x0011, 0x00FF)
SAT_ISL_MAX = 2                # neighbours per satellite in the flight code today (ring)

# the 868 MHz plan: pairs the bench uses, then free pairs in the band (uplink, downlink)
CHANNEL_PAIRS = [(868.1, 869.525), (868.3, 868.5), (868.7, 868.9), (869.1, 869.3), (867.1, 867.3), (867.5, 867.7), (867.9, 866.1), (866.3, 866.5)]


def _pqc():
    import sys
    if PQC not in sys.path:
        sys.path.insert(0, PQC)
    import pqsat_proto as P            # noqa
    return P


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self, db_path: str, keys_dir: str = KEYS, constellation: str = "pqsat8"):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.keys = keys_dir
        os.makedirs(self.keys, exist_ok=True)
        self.constellation = constellation
        work = os.environ.get("PQSAT_MANIFESTS") if os.environ.get("PQSAT_MANIFESTS_FIXED") else os.path.join(os.path.dirname(os.path.abspath(db_path)), "manifests")
        os.environ["PQSAT_MANIFESTS"] = work
        orbit.WORK = work
        self._schema()

    # ------------------------------------------------------------------ storage
    def _schema(self):
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS nodes(
            name TEXT PRIMARY KEY, kind TEXT NOT NULL, ident INTEGER NOT NULL UNIQUE,
            state TEXT NOT NULL, plane INTEGER, slot INTEGER, uplink_mhz REAL, downlink_mhz REAL,
            runs_on TEXT, lat REAL, lon REAL, alt_km REAL, policy TEXT, radio TEXT,
            cert_digest TEXT, cert_bytes INTEGER, not_after INTEGER, neighbours TEXT,
            created INTEGER, updated INTEGER, notes TEXT);
        CREATE TABLE IF NOT EXISTS node_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, t INTEGER, name TEXT, event TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS isl_keys(
            a TEXT, b TEXT, path TEXT, created INTEGER, retired INTEGER, PRIMARY KEY(a,b));
        CREATE TABLE IF NOT EXISTS revocations(
            ident INTEGER PRIMARY KEY, name TEXT, t INTEGER, reason TEXT, cert_digest TEXT);
        """)
        self.db.commit()

    def _event(self, name, event, detail=""):
        self.db.execute("INSERT INTO node_events(t,name,event,detail) VALUES(?,?,?,?)", (int(time.time()), name, event, detail))
        self.db.commit()

    def nodes(self, kind: Optional[str] = None) -> List[dict]:
        q = "SELECT * FROM nodes" + (" WHERE kind=?" if kind else "") + " ORDER BY kind, ident"
        rows = self.db.execute(q, (kind,) if kind else ()).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["neighbours"] = json.loads(d["neighbours"] or "[]")
            out.append(d)
        return out

    def node(self, name: str) -> Optional[dict]:
        r = self.db.execute("SELECT * FROM nodes WHERE name=?", (name,)).fetchone()
        if not r:
            return None
        d = dict(r); d["neighbours"] = json.loads(d["neighbours"] or "[]")
        return d

    def events(self, name: Optional[str] = None, limit: int = 100) -> List[dict]:
        q = "SELECT * FROM node_events" + (" WHERE name=?" if name else "") + " ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in self.db.execute(q, ((name, limit) if name else (limit,))).fetchall()]

    # ------------------------------------------------------------------ authority
    def authority(self):
        """The trusted authority (the ground station's key management role).  Created on
        first use and kept in the key store as ta.json, exactly as enrol.py writes it."""
        P = _pqc()
        p = os.path.join(self.keys, "ta.json")
        if os.path.exists(p):
            with open(p) as f:
                j = json.load(f)
            ta = P.TrustedAuthority.__new__(P.TrustedAuthority)
            ta.pk_sigma, ta.sk_sigma = bytes.fromhex(j["pk_sigma"]), bytes.fromhex(j["sk_sigma"])
            ta.pk_kappa, ta.sk_kappa = bytes.fromhex(j["pk_kappa"]), bytes.fromhex(j["sk_kappa"])
            ta.master_key = bytes.fromhex(j["master_key"])
            return ta
        ta = P.TrustedAuthority()
        with open(p, "w") as f:
            json.dump(dict(pk_sigma=ta.pk_sigma.hex(), pk_kappa=ta.pk_kappa.hex(), sk_sigma=ta.sk_sigma.hex(),
                           sk_kappa=ta.sk_kappa.hex(), master_key=ta.master_key.hex()), f, indent=1)
        self._event("authority", "created", "trusted authority key pairs written to ta.json")
        return ta

    def _ground_ident(self) -> int:
        g = self.nodes("ground")
        return g[0]["ident"] if g else ID_GS_DEFAULT

    # ------------------------------------------------------------------ enrolment
    def _enrol(self, name: str, ident: int, validity_days: int = 365, kind: str = "satellite") -> dict:
        """Enrol with the role of the node kind in the certificate (user 1, satellite 2, ground 3)."""
        P = _pqc()
        ta = self.authority()
        role = {"user": P.ROLE_UE, "satellite": P.ROLE_SAT, "ground": P.ROLE_GS}[kind]
        b = ta.enrol(ident, role, validity_days)
        with open(os.path.join(self.keys, name + ".cert"), "wb") as f:
            f.write(b["cert"].bundle())
        with open(os.path.join(self.keys, name + ".pickle"), "wb") as f:
            pickle.dump(b, f)
        return b

    def _write_sat_bundle(self, name: str, b: dict, id_gs: int):
        """ident 2 | id_gs 2 | sk_sigma | sk_kappa | ta_pk_sigma | own certificate bundle"""
        with open(os.path.join(self.keys, name + ".bundle"), "wb") as f:
            f.write(struct.pack(">HH", b["ident"], id_gs))
            f.write(b["sk_sigma"]); f.write(b["sk_kappa"]); f.write(b["ta_pk_sigma"]); f.write(b["cert"].bundle())

    def _isl_key(self, a: str, b: str) -> str:
        """Pairwise ISL key K_ISL(a,b): 32 random octets, file isl_<lo>_<hi>.key, stored
        under both nodes' auth directories at provisioning."""
        lo, hi = sorted([a, b], key=lambda n: self.node(n)["ident"] if self.node(n) else 0)
        fn = f"isl_{lo.lower().replace('-', '')}_{hi.lower().replace('-', '')}.key"
        p = os.path.join(self.keys, fn)
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(os.urandom(32))
        self.db.execute("INSERT OR REPLACE INTO isl_keys(a,b,path,created,retired) VALUES(?,?,?,?,NULL)", (lo, hi, p, int(time.time())))
        self.db.commit()
        return p

    def _next_scid(self) -> int:
        used = {n["ident"] for n in self.nodes("satellite")}
        for s in VALID_SCID:
            if s not in used:
                return s
        raise RegistryError("no free SCID")

    def _next_user_id(self) -> int:
        used = {n["ident"] for n in self.nodes("user")}
        for s in VALID_USER:
            if s not in used:
                return s
        raise RegistryError("no free user identity")

    def _next_channels(self):
        used = {(n["uplink_mhz"], n["downlink_mhz"]) for n in self.nodes("satellite")}
        for pair in CHANNEL_PAIRS:
            if pair not in used:
                return pair
        return CHANNEL_PAIRS[len(used) % len(CHANNEL_PAIRS)]     # channels are reused when more than 8 satellites

    def _ring_neighbours(self, plane: int, slot: int) -> List[str]:
        sats = [n for n in self.nodes("satellite") if n["plane"] == plane and n["state"] != "revoked"]
        if not sats:
            return []
        by_slot = sorted(sats, key=lambda n: n["slot"])
        slots = [n["slot"] for n in by_slot]
        prev = max([s for s in slots if s < slot], default=max(slots))
        nxt = min([s for s in slots if s > slot], default=min(slots))
        out = []
        for s in (prev, nxt):
            n = next(x for x in by_slot if x["slot"] == s)
            if n["name"] not in out and n["slot"] != slot:
                out.append(n["name"])
        return out[:SAT_ISL_MAX]

    # ------------------------------------------------------------------ add nodes
    def add_ground_station(self, name="Site A", ident=ID_GS_DEFAULT, lat=54.5973, lon=-5.9301, alt_km=0.02, radio="/dev/ttyACM0", validity_days=365) -> dict:
        if self.node(name):
            raise RegistryError(f"{name} exists")
        b = self._enrol("gs" if ident == ID_GS_DEFAULT else name.lower(), ident, validity_days, "ground")
        c = b["cert"]
        self.db.execute("INSERT INTO nodes(name,kind,ident,state,lat,lon,alt_km,radio,cert_digest,cert_bytes,not_after,neighbours,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (name, "ground", ident, "provisioned", lat, lon, alt_km, radio, c.digest().hex(), len(c.bundle()), getattr(c, "not_after", 0), "[]", int(time.time()), int(time.time())))
        self.db.commit(); self._event(name, "enrolled", f"ground station {ident:#06x}, certificate {len(c.bundle())} B")
        self._update_manifests()
        return self.node(name)

    def add_satellite(self, name: Optional[str] = None, scid: Optional[int] = None, plane: int = 0, slot: Optional[int] = None,
                      uplink_mhz: Optional[float] = None, downlink_mhz: Optional[float] = None, runs_on: str = "emulator",
                      neighbours: Optional[List[str]] = None, validity_days: int = 365, notes: str = "") -> dict:
        sats = self.nodes("satellite")
        scid = scid or self._next_scid()
        if scid not in VALID_SCID or any(n["ident"] == scid for n in sats):
            raise RegistryError(f"SCID {scid:#x} invalid or in use")
        name = name or f"SAT-{scid - 0x100}"
        if self.node(name):
            raise RegistryError(f"{name} exists")
        if slot is None:
            slot = max([n["slot"] for n in sats if n["plane"] == plane], default=-1) + 1
        if uplink_mhz is None or downlink_mhz is None:
            uplink_mhz, downlink_mhz = self._next_channels()
        if uplink_mhz == downlink_mhz:
            raise RegistryError("uplink and downlink must differ (frequency division duplex)")
        # 1 enrol
        b = self._enrol(name.lower().replace("-", ""), scid, validity_days, "satellite")
        self._write_sat_bundle(name.lower().replace("-", ""), b, self._ground_ident())
        c = b["cert"]
        # 2 record, then rebuild the ring and the pairwise keys
        self.db.execute("INSERT INTO nodes(name,kind,ident,state,plane,slot,uplink_mhz,downlink_mhz,runs_on,cert_digest,cert_bytes,not_after,neighbours,created,updated,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (name, "satellite", scid, "enrolled", plane, slot, uplink_mhz, downlink_mhz, runs_on, c.digest().hex(), len(c.bundle()), getattr(c, "not_after", 0), json.dumps(neighbours or []), int(time.time()), int(time.time()), notes))
        self.db.commit(); self._event(name, "enrolled", f"SCID {scid:#06x}, certificate {len(c.bundle())} B, digest {c.digest().hex()[:16]}")
        changed = self._rebuild_ring(explicit={name: neighbours} if neighbours else None)
        # 3 provision the new node and every neighbour whose ISL keys changed
        # every satellite gets the new certificate (end to end key transfer), so all are provisioned again
        for n in sorted(set([name]) | changed | {x["name"] for x in self.nodes("satellite") if x["state"] != "revoked"}):
            self.provision(n)
        self._update_manifests()
        return self.node(name)

    def _rebuild_ring(self, explicit: Optional[Dict[str, List[str]]] = None) -> set:
        """Recompute every satellite's neighbours from the ring order (per plane, by slot),
        honouring explicit neighbour lists, create missing pairwise keys and retire keys
        of pairs that are no longer adjacent.  Returns the names whose neighbours changed."""
        sats = [n for n in self.nodes("satellite") if n["state"] != "revoked"]
        changed = set()
        by_plane: Dict[int, List[dict]] = {}
        for n in sats:
            by_plane.setdefault(n["plane"], []).append(n)
        want: Dict[str, List[str]] = {}
        for plane, ns in by_plane.items():
            ns.sort(key=lambda x: x["slot"])
            k = len(ns)
            for i, n in enumerate(ns):
                nb = []
                if k > 1:
                    nb.append(ns[(i - 1) % k]["name"])
                if k > 2:
                    nb.append(ns[(i + 1) % k]["name"])
                want[n["name"]] = nb
        if explicit:
            for a, bs in explicit.items():
                want[a] = [b for b in bs if b in want][:SAT_ISL_MAX]
                for b in want[a]:
                    if a not in want[b]:
                        want[b] = (want[b] + [a])[-SAT_ISL_MAX:]
        now = int(time.time())
        pairs = set()
        for n in sats:
            new = want.get(n["name"], [])
            if new != n["neighbours"]:
                changed.add(n["name"])
                self.db.execute("UPDATE nodes SET neighbours=?, updated=? WHERE name=?", (json.dumps(new), now, n["name"]))
            for b in new:
                pairs.add(tuple(sorted([n["name"], b], key=lambda x: self.node(x)["ident"])))
        for a, b in pairs:
            self._isl_key(a, b)
        for r in self.db.execute("SELECT a,b FROM isl_keys WHERE retired IS NULL").fetchall():
            if (r["a"], r["b"]) not in pairs:
                self.db.execute("UPDATE isl_keys SET retired=? WHERE a=? AND b=?", (now, r["a"], r["b"]))
                changed.update([r["a"], r["b"]])
        self.db.commit()
        for n in changed:
            self._event(n, "isl_rekeyed", f"neighbours now {want.get(n, [])}")
        return changed

    def add_user(self, name: Optional[str] = None, ident: Optional[int] = None, lat=54.584, lon=-5.933, alt_km=0.02,
                 radio: str = "/dev/ttyACM1", policy: str = "longest_remaining", validity_days: int = 365, notes: str = "") -> dict:
        ident = ident or self._next_user_id()
        if ident not in VALID_USER or any(n["ident"] == ident for n in self.nodes("user")):
            raise RegistryError(f"user identity {ident:#x} invalid or in use")
        name = name or f"USER{ident - 0x10}"
        if self.node(name):
            raise RegistryError(f"{name} exists")
        b = self._enrol(name.lower(), ident, validity_days, "user")
        c = b["cert"]
        self.db.execute("INSERT INTO nodes(name,kind,ident,state,lat,lon,alt_km,radio,policy,cert_digest,cert_bytes,not_after,neighbours,created,updated,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (name, "user", ident, "enrolled", lat, lon, alt_km, radio, policy, c.digest().hex(), len(c.bundle()), getattr(c, "not_after", 0), "[]", int(time.time()), int(time.time()), notes))
        self.db.commit(); self._event(name, "enrolled", f"user {ident:#06x}, certificate {len(c.bundle())} B")
        self.provision(name)
        self._update_manifests()
        return self.node(name)

    # ------------------------------------------------------------------ provisioning
    def provision(self, name: str) -> dict:
        """Write the files the node loads at start.  Satellites: an auth directory with the
        bundle, the ground and user certificates and its ISL keys, plus an environment file
        for the emulator or an SD card bundle for a board.  Users: the pickle and the peer
        certificates for the terminal library."""
        n = self.node(name)
        if not n:
            raise RegistryError(f"{name} unknown")
        out_dir = os.path.join(self.keys, "provision", name)
        os.makedirs(out_dir, exist_ok=True)
        stem = name.lower().replace("-", "")
        files = []
        if n["kind"] == "satellite":
            auth = os.path.join(out_dir, "auth"); os.makedirs(auth, exist_ok=True)
            for src in (stem + ".bundle", "gs.cert"):
                if os.path.exists(os.path.join(self.keys, src)):
                    self._cp(os.path.join(self.keys, src), os.path.join(auth, src if src != stem + ".bundle" else "sat.bundle")); files.append(src)
            for u in self.nodes("user"):
                src = u["name"].lower() + ".cert"
                if os.path.exists(os.path.join(self.keys, src)):
                    self._cp(os.path.join(self.keys, src), os.path.join(auth, src)); files.append(src)
            # certificates of every satellite (sat1.cert .. sat8.cert): the end to end key
            # transfer encapsulates to the receiver's key and verifies the sender's signature
            for o in self.nodes("satellite"):
                src = o["name"].lower().replace("-", "") + ".cert"
                if os.path.exists(os.path.join(self.keys, src)):
                    self._cp(os.path.join(self.keys, src), os.path.join(auth, src)); files.append(src)
            peers = []
            for nb in n["neighbours"]:
                lo, hi = sorted([name, nb], key=lambda x: self.node(x)["ident"])
                kp = f"isl_{lo.lower().replace('-', '')}_{hi.lower().replace('-', '')}.key"
                if os.path.exists(os.path.join(self.keys, kp)):
                    self._cp(os.path.join(self.keys, kp), os.path.join(auth, kp)); files.append(kp)
                    peers.append(f"{self.node(nb)['ident']:#x}:AUTH_DIR/{kp}")
            gs_peer = self._gs_peer(name)
            env = dict(SAT_SCID=f"{n['ident']:#x}", SAT_BUNDLE="sat", SAT_AUTH_DIR="AUTH_DIR", SAT_ISL_PEERS=",".join(peers),
                       SAT_GS_PEER=(f"{gs_peer:#x}" if gs_peer else ""), SAT_UPLINK_MHZ=n["uplink_mhz"], SAT_DOWNLINK_MHZ=n["downlink_mhz"], SAT_AUTH_FRESH_S=900)
            with open(os.path.join(out_dir, "satellite.env"), "w") as f:
                for k, v in env.items():
                    f.write(f"{k}={v}\n")
            files.append("satellite.env")
            if n["runs_on"].lower().startswith("versal") or n["runs_on"].lower().startswith("board"):
                tgz = os.path.join(out_dir, f"sd_{stem}.tgz")
                with tarfile.open(tgz, "w:gz") as tf:
                    tf.add(auth, arcname=f"cpu{self._cpu_index(name)}/auth")
                    unit = os.path.join(out_dir, f"sat{self._cpu_index(name)}.service")
                    with open(unit, "w") as f:
                        f.write(self._unit(name, env))
                    tf.add(unit, arcname=f"etc/systemd/system/sat{self._cpu_index(name)}.service")
                files.append(os.path.basename(tgz))
        elif n["kind"] == "user":
            for src in (stem + ".pickle", stem + ".cert", "gs.cert"):
                if os.path.exists(os.path.join(self.keys, src)):
                    self._cp(os.path.join(self.keys, src), os.path.join(out_dir, src)); files.append(src)
            for s in self.nodes("satellite"):
                src = s["name"].lower().replace("-", "") + ".cert"
                if os.path.exists(os.path.join(self.keys, src)):
                    self._cp(os.path.join(self.keys, src), os.path.join(out_dir, src)); files.append(src)
            with open(os.path.join(out_dir, "terminal.env"), "w") as f:
                f.write(f"PQSAT_UE_PORT={n['radio']}\nPQSAT_UE_ID={n['ident']:#x}\nPQSAT_UE_POLICY={n['policy']}\n")
            files.append("terminal.env")
        else:
            for src in ("gs.pickle", "gs.cert", "ta.json"):
                if os.path.exists(os.path.join(self.keys, src)):
                    self._cp(os.path.join(self.keys, src), os.path.join(out_dir, src)); files.append(src)
        self.db.execute("UPDATE nodes SET state=CASE WHEN state IN ('enrolled','provisioned') THEN 'provisioned' ELSE state END, updated=? WHERE name=?", (int(time.time()), name))
        self.db.commit(); self._event(name, "provisioned", ", ".join(files))
        return dict(name=name, dir=out_dir, files=files)

    def _gs_peer(self, name: str) -> Optional[int]:
        """The neighbour through which this satellite reaches the ground station: the one
        closer along the ring to the satellite whose role is feeder (the lowest SCID on the
        bench; in orbit the orchestrator overrides it per slot)."""
        n = self.node(name)
        sats = [s for s in self.nodes("satellite") if s["state"] != "revoked"]
        if not sats or not n["neighbours"]:
            return None
        feeder = min(sats, key=lambda s: s["ident"])
        if feeder["name"] == name:
            return None
        return self.node(n["neighbours"][0])["ident"]

    def _cpu_index(self, name: str) -> int:
        n = self.node(name)
        return n["ident"] - 0x100

    def _unit(self, name: str, env: dict) -> str:
        i = self._cpu_index(name)
        lines = [f"Environment={k}={str(v).replace('AUTH_DIR', f'/root/cpu{i}/auth')}" for k, v in env.items() if v != ""]
        return ("[Unit]\nDescription=%s flight software\nRequires=satmux.service\nAfter=satmux.service\n\n[Service]\nType=simple\nWorkingDirectory=/root/cpu%d\n"
                "Environment=SAT_RF_DEVICE=/tmp/sat%d.tty\nEnvironment=LD_LIBRARY_PATH=/root/cpu%d\n%s\nExecStart=/root/cpu%d/core-cpu%d --cpuid %d --cpuname cpu%d\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n"
                % (name, i, i, i, "\n".join(lines), i, i, i, i))

    @staticmethod
    def _cp(a, b):
        with open(a, "rb") as f, open(b, "wb") as g:
            g.write(f.read())

    # ------------------------------------------------------------------ state changes
    def mark(self, name: str, state: str, detail: str = ""):
        if state not in ("enrolled", "provisioned", "deployed", "active", "revoked"):
            raise RegistryError("unknown state")
        self.db.execute("UPDATE nodes SET state=?, updated=? WHERE name=?", (state, int(time.time()), name))
        self.db.commit(); self._event(name, state, detail)

    def heard(self, ident: int):
        """Called by the platform when a node's housekeeping or terminal attach is seen."""
        r = self.db.execute("SELECT name,state FROM nodes WHERE ident=?", (ident,)).fetchone()
        if r and r["state"] in ("provisioned", "deployed"):
            self.mark(r["name"], "active", "heard on the link")

    def revoke(self, name: str, reason: str = "operator") -> dict:
        n = self.node(name)
        if not n:
            raise RegistryError(f"{name} unknown")
        self.db.execute("INSERT OR REPLACE INTO revocations(ident,name,t,reason,cert_digest) VALUES(?,?,?,?,?)", (n["ident"], name, int(time.time()), reason, n["cert_digest"]))
        self.db.execute("UPDATE isl_keys SET retired=? WHERE a=? OR b=?", (int(time.time()), name, name))
        for nb in n["neighbours"]:
            o = self.node(nb)
            if o:
                o["neighbours"] = [x for x in o["neighbours"] if x != name]
                self.db.execute("UPDATE nodes SET neighbours=?, updated=? WHERE name=?", (json.dumps(o["neighbours"]), int(time.time()), nb))
                self._event(nb, "isl_retired", f"pairwise key with {name} retired")
        self.mark(name, "revoked", reason)
        for nb in self._rebuild_ring():
            if self.node(nb)["state"] != "revoked":
                self.provision(nb)
        self._write_crl()
        self._update_manifests()
        return self.crl()

    def crl(self) -> dict:
        rows = [dict(r) for r in self.db.execute("SELECT * FROM revocations ORDER BY t").fetchall()]
        return dict(issued=int(time.time()), revoked=rows)

    def _write_crl(self):
        """crl.json: the revocation list, signed by the authority with ML-DSA-65 so the
        satellites and terminals can verify it before applying it."""
        P = _pqc()
        ta = self.authority()
        body = json.dumps(self.crl(), sort_keys=True).encode()
        try:
            from pqsat import ML_DSA_65 as DSA
            sig = DSA.sign(body, ta.sk_sigma).hex()
        except Exception:
            sig = ""
        with open(os.path.join(self.keys, "crl.json"), "w") as f:
            json.dump(dict(body=body.decode(), sig=sig, digest=hashlib.sha3_256(body).hexdigest()), f, indent=1)
        # crl.bin: the same list as the protocol message the satellites and terminals install
        # (type 0x0A, pqsat_proto.enc_crl).  Uplink it with gs/send_crl.py or put it in a
        # satellite's auth folder; an older list is refused, so a revocation cannot be undone
        # by replaying an earlier file.
        try:
            idents = [int(r["ident"]) for r in self.crl()["revoked"]]
            with open(os.path.join(self.keys, "crl.bin"), "wb") as f:
                f.write(P.enc_crl(ta.sk_sigma, idents))
        except Exception as e:                       # the JSON list above stays authoritative
            print("crl.bin not written:", e)

    def rotate(self, name: str, validity_days: int = 365) -> dict:
        """Issue a new certificate and key pairs for a node (key rotation) and reprovision it."""
        n = self.node(name)
        if not n:
            raise RegistryError(f"{name} unknown")
        stem = name.lower().replace("-", "") if n["kind"] != "ground" else "gs"
        b = self._enrol(stem, n["ident"], validity_days, n["kind"])
        if n["kind"] == "satellite":
            self._write_sat_bundle(stem, b, self._ground_ident())
        c = b["cert"]
        self.db.execute("UPDATE nodes SET cert_digest=?, cert_bytes=?, not_after=?, state='provisioned', updated=? WHERE name=?",
                        (c.digest().hex(), len(c.bundle()), getattr(c, "not_after", 0), int(time.time()), name))
        self.db.commit(); self._event(name, "rotated", f"new certificate, digest {c.digest().hex()[:16]}")
        return self.provision(name)

    # ------------------------------------------------------------------ manifests
    def _update_manifests(self):
        """Keep the constellation, ground and user manifests in step with the registry so
        the orbit layer and the orchestrator see the nodes the dashboard added."""
        try:
            m = orbit.load_manifest(self.constellation)
        except Exception:
            m = dict(name=self.constellation, walker=dict(satellites=0, planes=1, phasing=0), altitude_km=1414, inclination_deg=87.9,
                     raan0_deg=-100, min_elevation_deg=10, isl=dict(topology="ring"), radio=dict(profile="SF9", adaptive_sf=False), satellites=[])
        sats = [n for n in self.nodes("satellite") if n["state"] != "revoked"]
        if sats:
            m["satellites"] = [dict(name=n["name"], scid=n["ident"], plane=n["plane"], slot=n["slot"], uplink_mhz=n["uplink_mhz"], downlink_mhz=n["downlink_mhz"],
                                    runs_on=n["runs_on"], neighbours=n["neighbours"]) for n in sats]
            planes = max(n["plane"] for n in sats) + 1
            m["walker"] = dict(satellites=len(sats), planes=planes, phasing=m.get("walker", {}).get("phasing", 0))
            m["isl"]["pairs"] = sorted({tuple(sorted([n["name"], nb])) for n in sats for nb in n["neighbours"]})
            m["isl"]["pairs"] = [list(p) for p in m["isl"]["pairs"]]
        orbit.save_manifest(m, self.constellation)
        orbit.save_manifest(dict(ground_stations=[dict(name=n["name"], id=n["ident"], lat=n["lat"], lon=n["lon"], alt_km=n["alt_km"], min_elevation_deg=10, radio=n["radio"]) for n in self.nodes("ground")] or orbit.load_manifest("ground")["ground_stations"]), "ground")
        orbit.save_manifest(dict(users=[dict(name=n["name"], id=n["ident"], lat=n["lat"], lon=n["lon"], alt_km=n["alt_km"], radio=n["radio"], serving_policy=n["policy"]) for n in self.nodes("user") if n["state"] != "revoked"] or orbit.load_manifest("users")["users"]), "users")

    # ------------------------------------------------------------------ bootstrap
    def bootstrap_from_manifest(self, name: str = "pqsat8", ground: str = "ground", users: str = "users") -> List[dict]:
        """Enrol every node a manifest lists that the registry does not have yet (first
        start of a constellation).  Existing key files are kept, so the bench's sat1, sat2,
        gs and ue1 keys stay valid."""
        m = orbit.load_manifest(name); g = orbit.load_manifest(ground); u = orbit.load_manifest(users)
        added = []
        for gs in g["ground_stations"]:
            if not self.node(gs["name"]):
                if os.path.exists(os.path.join(self.keys, "gs.pickle")):       # reuse the bench authority and keys
                    self._adopt(gs["name"], "ground", gs.get("id", ID_GS_DEFAULT), "gs", lat=gs["lat"], lon=gs["lon"], alt_km=gs.get("alt_km", 0), radio=gs.get("radio", ""))
                else:
                    self.add_ground_station(gs["name"], gs.get("id", ID_GS_DEFAULT), gs["lat"], gs["lon"], gs.get("alt_km", 0), gs.get("radio", ""))
                added.append(gs["name"])
        for s in orbit.walker_satellites(m):
            if not self.node(s["name"]):
                stem = s["name"].lower().replace("-", "")
                if os.path.exists(os.path.join(self.keys, stem + ".pickle")):
                    self._adopt(s["name"], "satellite", s["scid"], stem, plane=s["plane"], slot=s["slot"], uplink_mhz=s["uplink_mhz"], downlink_mhz=s["downlink_mhz"], runs_on=s.get("runs_on", "emulator"))
                    pass
                else:
                    self.add_satellite(s["name"], s["scid"], s["plane"], s["slot"], s["uplink_mhz"], s["downlink_mhz"], s.get("runs_on", "emulator"), s.get("neighbours"))
                added.append(s["name"])
        for us in u["users"]:
            if not self.node(us["name"]):
                stem = us["name"].lower()
                if os.path.exists(os.path.join(self.keys, stem + ".pickle")):
                    self._adopt(us["name"], "user", us.get("id", 0x11), stem, lat=us["lat"], lon=us["lon"], alt_km=us.get("alt_km", 0), radio=us.get("radio", ""), policy=us.get("serving_policy", "longest_remaining"))
                    self.provision(us["name"])
                else:
                    self.add_user(us["name"], us.get("id"), us["lat"], us["lon"], us.get("alt_km", 0), us.get("radio", "/dev/ttyACM1"), us.get("serving_policy", "longest_remaining"))
                added.append(us["name"])
        self._rebuild_ring()
        for s in self.nodes("satellite"):
            self.provision(s["name"])
        self._update_manifests()
        return added

    def _adopt(self, name, kind, ident, stem, **cols):
        _pqc()
        with open(os.path.join(self.keys, stem + ".pickle"), "rb") as f:
            b = pickle.load(f)
        c = b["cert"]
        keys = ["name", "kind", "ident", "state", "cert_digest", "cert_bytes", "not_after", "neighbours", "created", "updated"] + list(cols)
        vals = [name, kind, ident, "provisioned", c.digest().hex(), len(c.bundle()), getattr(c, "not_after", 0), "[]", int(time.time()), int(time.time())] + list(cols.values())
        self.db.execute(f"INSERT INTO nodes({','.join(keys)}) VALUES({','.join('?' * len(keys))})", vals)
        self.db.commit(); self._event(name, "adopted", "existing keys taken into the registry")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="node registry: enrol, provision, revoke")
    ap.add_argument("--db", default="testbed.db"); ap.add_argument("--keys", default=KEYS)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list"); b = sub.add_parser("bootstrap"); b.add_argument("--constellation", default="pqsat8")
    s = sub.add_parser("add-satellite"); s.add_argument("--name"); s.add_argument("--scid", type=lambda x: int(x, 0)); s.add_argument("--plane", type=int, default=0); s.add_argument("--slot", type=int); s.add_argument("--runs-on", default="emulator")
    u = sub.add_parser("add-user"); u.add_argument("--name"); u.add_argument("--id", type=lambda x: int(x, 0)); u.add_argument("--lat", type=float, default=54.584); u.add_argument("--lon", type=float, default=-5.933); u.add_argument("--radio", default="/dev/ttyACM1")
    r = sub.add_parser("revoke"); r.add_argument("name"); r.add_argument("--reason", default="operator")
    a = ap.parse_args()
    reg = Registry(a.db, a.keys)
    if a.cmd == "bootstrap":
        print("added", reg.bootstrap_from_manifest(a.constellation))
    elif a.cmd == "add-satellite":
        print(json.dumps(reg.add_satellite(a.name, a.scid, a.plane, a.slot, runs_on=a.runs_on), indent=1))
    elif a.cmd == "add-user":
        print(json.dumps(reg.add_user(a.name, a.id, a.lat, a.lon, radio=a.radio), indent=1))
    elif a.cmd == "revoke":
        print(json.dumps(reg.revoke(a.name, a.reason), indent=1))
    for n in reg.nodes():
        print(f"{n['kind']:9s} {n['name']:8s} {n['ident']:#06x} {n['state']:11s} runs on {n['runs_on'] or '-':9s} neighbours {n['neighbours']}")

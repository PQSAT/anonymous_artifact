"""The platform: one object that builds the nodes on a backend, runs an experiment with
a protocol under a link model, and keeps the records.

    from pqsat_testbed import Platform
    p = Platform(db="testbed.db")
    rid = p.run("handshake", backend="emulator", topology="constellation", protocol="pqsat",
                link="clean", mode="ref", runs=3)
    print(p.db.run(rid)["summary"])
"""
import os
import threading
import time
import traceback
import uuid

from pqsat_testbed import __version__
from pqsat_testbed.plugins import PROTOCOLS, LINKS, EXPERIMENTS, load_all
from pqsat_testbed.schema import Database


class Platform:
    def __init__(self, db="testbed.db", log_dir="."):
        load_all()
        self.db = Database(db)
        self.log_dir = log_dir
        self.listeners = []          # callables receiving live events
        self.current = None          # nodes of the running experiment, for the live state
        self.lock = threading.Lock()  # one experiment at a time (one board, one channel)

    def subscribe(self, fn):
        self.listeners.append(fn)

    def _live(self, run_id, ev):
        ev = dict(ev, run_id=run_id, t=time.time())
        for fn in list(self.listeners):
            try:
                fn(ev)
            except Exception:
                pass

    def build(self, backend, topology, link="clean", mode="ref", preload=True, sdls=True, protocol="pqsat",
              **kw):
        proto = PROTOCOLS[protocol]
        if backend == "emulator":
            from pqsat_testbed.backends.emulator import EmulatorNodes
            nodes = EmulatorNodes(topology, LINKS[link](), mode=mode, preload=preload, sdls=sdls,
                                  external_sat=(proto.satellite_role == "python"))
            if proto.satellite_role == "python":
                nodes.attach_satellite_sessions(proto())
        elif backend == "hardware":
            from pqsat_testbed.backends.hardware import HardwareNodes
            nodes = HardwareNodes(topology, log_dir=self.log_dir, **{k: v for k, v in kw.items()
                                                                     if k in ("gs_port", "ue_port")})
        else:
            raise ValueError(f"unknown backend {backend}")
        return nodes

    def run(self, experiment, backend="emulator", topology="single", protocol="pqsat", link="clean", mode="ref",
            note="", run_id=None, **params):
        """Run one experiment to completion and return its run id."""
        run_id = run_id or time.strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
        config = dict(experiment=experiment, backend=backend, topology=topology, protocol=protocol, link=link,
                      mode=mode, params=params)
        self.db.start_run(run_id, backend, topology, protocol, experiment, mode, config, __version__, note)
        with self.lock:
            self._live(run_id, dict(event="run_start", config=config))
            nodes = None
            try:
                exp = EXPERIMENTS[experiment]()
                if exp.needs_nodes:
                    nodes = self.build(backend, topology, link=link, mode=mode, protocol=protocol,
                                       preload=params.get("preload", True), sdls=params.get("sdls", True), **params)
                    self.current = nodes
                    if not nodes.bring_up():
                        raise RuntimeError("links did not come up (housekeeping, COP-1 or SET_TIME failed)")
                    self._live(run_id, dict(event="links_up", state=nodes.state()))
                summary = exp.run(self, nodes, self.db, run_id, lambda ev: self._live(run_id, ev),
                                  protocol=protocol, mode=mode, **{k: v for k, v in params.items()
                                                                    if k not in ("gs_port", "ue_port")})
                self.db.finish_run(run_id, "done", summary)
                self._live(run_id, dict(event="run_done", summary=summary))
            except Exception as e:
                tb = traceback.format_exc()
                self.db.finish_run(run_id, "failed", dict(error=str(e), traceback=tb))
                self._live(run_id, dict(event="run_failed", error=str(e)))
            finally:
                if nodes is not None:
                    nodes.close()
                self.current = None
        return run_id

    def replay(self, run_id):
        """Rerun a recorded run with its stored configuration on the emulator."""
        r = self.db.run(run_id)
        if r is None:
            raise KeyError(run_id)
        c = r["config"]
        return self.run(c["experiment"], backend="emulator", topology=c["topology"], protocol=c["protocol"],
                        link=c["link"], mode=c["mode"], note=f"replay of {run_id}", **c.get("params", {}))

    def state(self):
        n = self.current
        return n.state() if n is not None else dict(backend=None, idle=True)

    def import_dir(self, directory, backend="hardware"):
        """Import every campaign JSON in a directory (past results)."""
        ids = []
        for f in sorted(os.listdir(directory)):
            if f.endswith(".json"):
                top = "constellation" if "const" in f else "single"
                be = "hardware" if "hw" in f else ("emulator" if "loss" in f else backend)
                try:
                    ids.append(self.db.import_campaign(os.path.join(directory, f), be, top))
                except Exception:
                    pass
        return ids

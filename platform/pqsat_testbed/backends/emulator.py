"""Emulator backend: the real flight satellite core (satsim, compiled from the cFS
application sources with NASA CryptoLib and libpqsat) as one process per satellite, the
real terminal library for the user and the ground, simulated LoRa channels with the
measured half duplex behaviour, a simulated ISL.

Topologies
    single          user and ground on SAT-1
    constellation   ground on SAT-1, user on SAT-2, ISL between them (SAT-2 reaches the
                    ground through SAT-1 and hands it the session key)
"""
import os
import threading
import time

from pqsat_testbed import paths
from ccsds_link import Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1
from sim_link import SimSatellite, SimModem

SCID = dict(sat1=0x101, sat2=0x102, sat3=0x103)


class EmulatorNodes:
    def __init__(self, topology, link, mode="ref", preload=True, sdls=True, external_sat=False, adversary=True):
        self.topology = topology
        env = dict(SAT_AUTH_DIR=paths.KEYS)
        if mode == "ref":
            env["SAT_AUTH_REF"] = "1"
        if preload:
            env["SAT_AUTH_PRELOAD_UE"] = "1"
        if not sdls:
            env["SAT_NO_SDLS"] = "1"
        if external_sat:
            env["SAT_AUTH_EXTERNAL"] = "1"
        env.update(link.env())
        for k in ("SAT_AUTH_REF", "SAT_AUTH_PRELOAD_UE", "SAT_NO_SDLS", "SAT_AUTH_EXTERNAL", "SIM_SAT_HALF_DUPLEX",
                  "SAT_TX_PACE_PCT", "SAT_RX_WINDOW_MS"):
            os.environ.pop(k, None)
        os.environ.update({k: v for k, v in env.items() if k == "SIM_SAT_HALF_DUPLEX"})
        isl_key = os.path.join(paths.KEYS, "isl_sat1_sat2.key")
        isl_key23 = os.path.join(paths.KEYS, "isl_sat2_sat3.key")
        self.sims = {}
        if topology == "chain":
            # user on SAT-3, SAT-2 routing with two neighbours, ground on SAT-1
            e1 = dict(env, SAT_SCID="0x101", SAT_ISL_PEERS=f"0x102:{isl_key}")
            e2 = dict(env, SAT_SCID="0x102", SAT_ISL_PEERS=f"0x101:{isl_key},0x103:{isl_key23}", SAT_GS_PEER="0x101")
            e3 = dict(env, SAT_SCID="0x103", SAT_BUNDLE="sat3", SAT_ISL_PEERS=f"0x102:{isl_key23}", SAT_GS_PEER="0x102")
            for n, e in (("sat1", e1), ("sat2", e2), ("sat3", e3)):
                self.sims[n] = SimSatellite(paths.SATSIM, loss=link.loss, env=e, name=n.upper().replace("SAT", "SAT-"),
                                            isl_delay_ms=link.isl_delay_ms)
            self.sims["sat1"].isl_peers = {0: self.sims["sat2"]}
            self.sims["sat2"].isl_peers = {0: self.sims["sat1"], 1: self.sims["sat3"]}
            self.sims["sat3"].isl_peers = {0: self.sims["sat2"]}
            serving = "sat3"
        elif topology == "single":
            e1 = dict(env, SAT_SCID="0x101")
            self.sims["sat1"] = SimSatellite(paths.SATSIM, loss=link.loss, env=e1, name="SAT-1",
                                             isl_delay_ms=link.isl_delay_ms)
            serving = "sat1"
        else:
            e1 = dict(env, SAT_SCID="0x101", SAT_ISL_PEER="0x102", SAT_ISL_KEY=isl_key)
            e2 = dict(env, SAT_SCID="0x102", SAT_ISL_PEER="0x101", SAT_GS_VIA_ISL="1", SAT_ISL_KEY=isl_key)
            self.sims["sat1"] = SimSatellite(paths.SATSIM, loss=link.loss, env=e1, name="SAT-1",
                                             isl_delay_ms=link.isl_delay_ms)
            self.sims["sat2"] = SimSatellite(paths.SATSIM, loss=link.loss, env=e2, name="SAT-2",
                                             isl_delay_ms=link.isl_delay_ms)
            self.sims["sat1"].isl_peer, self.sims["sat2"].isl_peer = self.sims["sat2"], self.sims["sat1"]
            serving = "sat2"
        self.serving = serving
        self.gs = Terminal(SimModem(self.sims["sat1"], "GS", loss=link.loss), ADDR_GS, TC_VC_GROUND,
                           scid=SCID["sat1"], name="GS", show_hk=False, show_relay=False).start()
        self.ue = Terminal(SimModem(self.sims[serving], "USER1", loss=link.loss), ADDR_USER1, TC_VC_USER1,
                           scid=SCID[serving], name="USER1", show_hk=False, show_relay=False).start()
        self.adversary = None
        if adversary:
            self.adversary = Terminal(SimModem(self.sims[serving], "ADV"), ADDR_USER1, TC_VC_USER1,
                                      scid=SCID[serving], name="ADV", show_hk=False, show_relay=False).start()
        self.sats = {n: dict(scid=SCID[n], sim=s) for n, s in self.sims.items()}
        self.backend = "emulator"
        self._ext = {}
        self._run = True

    # ---------------- link bring up ----------------
    def bring_up(self, timeout=30):
        end = time.time() + timeout
        while (self.gs.hk is None or self.ue.hk is None) and time.time() < end:
            time.sleep(0.2)
        if self.gs.hk is None or self.ue.hk is None:
            return False
        if not (self.gs.init_cop() and self.ue.init_cop()):
            return False
        if self.gs.set_time() != "OK":
            return False
        if self.topology != "single":
            end = time.time() + 35
            while time.time() < end and not any("ISL: clock set" in l for l in self.sims[self.serving].log):
                time.sleep(0.3)
        return True

    # ---------------- Python satellite roles (external protocol) ----------------
    def attach_satellite_sessions(self, protocol):
        """For a protocol whose satellite role runs in Python: pump authentication messages
        from each satellite core to the plug in's session and send the answers back."""
        for name, sim in self.sims.items():
            sess = protocol.satellite_session(name)
            self._ext[name] = sess
            threading.Thread(target=self._pump, args=(name, sim, sess), daemon=True).start()

    def _pump(self, name, sim, sess):
        seen = 0
        while self._run:
            if len(sim.auth_rx) > seen:
                t, src, msg = sim.auth_rx[seen]
                seen += 1
                for dst, out in sess.handle(src, msg):
                    sim.send_auth(dst, out)
                sk = sess.session_key()
                if sk is not None and not getattr(sess, "_keyed", False):
                    sess._keyed = True
                    sim.sdls_start(sk)
            else:
                time.sleep(0.05)

    # ---------------- handover ----------------
    def move_user(self, to_sat):
        """The user retunes to another satellite: new terminal on that satellite's channel."""
        self.ue._run = False
        time.sleep(0.5)
        self.serving = to_sat
        self.ue = Terminal(SimModem(self.sims[to_sat], "USER1"), ADDR_USER1, TC_VC_USER1, scid=SCID[to_sat],
                           name="USER1", show_hk=False, show_relay=False).start()
        end = time.time() + 25
        while self.ue.hk is None and time.time() < end:
            time.sleep(0.2)
        return self.ue.hk is not None and self.ue.init_cop()

    def logs(self):
        return {n: (list(s.log), list(s.log_t)) for n, s in self.sims.items()}

    def state(self):
        return dict(backend="emulator", topology=self.topology, serving=self.serving,
                    sats={n: dict(scid=f"{SCID[n]:#x}", isl_tx=s.isl_frames_tx, log_lines=len(s.log))
                          for n, s in self.sims.items()},
                    gs=dict(hk=self.gs.hk, stats=self.gs.stats, sdls=self.gs.sdls is not None),
                    ue=dict(hk=self.ue.hk, stats=self.ue.stats, sdls=self.ue.sdls is not None))

    def close(self):
        self._run = False
        for t in (self.gs, self.ue, self.adversary):
            if t is not None:
                t._run = False
        for s in self.sims.values():
            s.close()

"""Hardware backend: the Versal board (SAT-1, and SAT-2 in constellation mode) through
the laptop bridge and the LoRa radios; the user and ground terminals on T-Beams attached
to this computer (the Linux laptop in the laboratory).

The bridge must be running on the Windows laptop (sat_bridge.py --versal ... --radio ...
and --radio2 ... for the constellation) and the board started with sat1_start.sh or
constellation_start.sh.  Ports: PQSAT_GS_PORT (default /dev/ttyACM0) and PQSAT_UE_PORT
(default /dev/ttyACM1).
"""
import os
import time

from pqsat_testbed import paths  # noqa: F401
from ccsds_link import (SerialLink, Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1, SCID_SAT1,
                        SCID_SAT2, SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ, UPLINK_MHZ, DOWNLINK_MHZ)

SCID = dict(sat1=SCID_SAT1, sat2=SCID_SAT2)
FREQ = dict(sat1=(UPLINK_MHZ, DOWNLINK_MHZ), sat2=(SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ))


class HardwareNodes:
    def __init__(self, topology, link=None, gs_port=None, ue_port=None, log_dir=".", **_):
        self.topology = topology
        self.gs_port = gs_port or os.environ.get("PQSAT_GS_PORT", "/dev/ttyACM0")
        self.ue_port = ue_port or os.environ.get("PQSAT_UE_PORT", "/dev/ttyACM1")
        self.serving = "sat2" if topology == "constellation" else "sat1"
        self.log_dir = log_dir
        self.gs = Terminal(SerialLink(self.gs_port), ADDR_GS, TC_VC_GROUND, scid=SCID_SAT1, name="GS",
                           log_path=os.path.join(log_dir, "gs_link_log.csv"), show_hk=False, show_relay=False).start()
        self.ue_link = None
        self._open_user(self.serving)
        self.sats = {"sat1": dict(scid=SCID_SAT1, sim=None)}
        if topology == "constellation":
            self.sats["sat2"] = dict(scid=SCID_SAT2, sim=None)
        self.adversary = None
        self.backend = "hardware"

    def _open_user(self, sat):
        up, down = FREQ[sat]
        self.ue_link = SerialLink(self.ue_port, tx_mhz=up, rx_mhz=down)
        self.ue = Terminal(self.ue_link, ADDR_USER1, TC_VC_USER1, scid=SCID[sat], name="USER1",
                           log_path=os.path.join(self.log_dir, "ue_link_log.csv"), show_hk=False,
                           show_relay=False).start()
        self.serving = sat

    def bring_up(self, timeout=40):
        end = time.time() + timeout
        while (self.gs.hk is None or self.ue.hk is None) and time.time() < end:
            time.sleep(0.2)
        if self.gs.hk is None or self.ue.hk is None:
            return False
        if not (self.gs.init_cop() and self.ue.init_cop()):
            return False
        if self.gs.set_time() != "OK":
            return False
        if self.topology == "constellation":
            time.sleep(12)   # SAT-2 takes its clock from SAT-1 over the ISL within one housekeeping period
        return True

    def attach_satellite_sessions(self, protocol):
        raise RuntimeError("the hardware runs the flight satellite module; Python satellite roles are emulator only")

    def move_user(self, to_sat):
        """Handover: retune the user's radio to the other satellite's channels."""
        self.ue._run = False
        time.sleep(0.5)
        self.ue_link.close()
        self._open_user(to_sat)
        end = time.time() + 40
        while self.ue.hk is None and time.time() < end:
            time.sleep(0.2)
        return self.ue.hk is not None and self.ue.init_cop()

    def logs(self):
        return {}   # satellite logs reach the bridge CSV on the Windows laptop; attach them by hand

    def state(self):
        return dict(backend="hardware", topology=self.topology, serving=self.serving,
                    sats={n: dict(scid=f"{s['scid']:#x}") for n, s in self.sats.items()},
                    gs=dict(hk=self.gs.hk, stats=self.gs.stats, sdls=self.gs.sdls is not None),
                    ue=dict(hk=self.ue.hk, stats=self.ue.stats, sdls=self.ue.sdls is not None))

    def close(self):
        self.gs._run = self.ue._run = False
        time.sleep(0.3)
        try:
            self.gs.link.close()
            self.ue_link.close()
        except Exception:
            pass

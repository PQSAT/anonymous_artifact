"""Modelled orbit conditions on the real radio link.

The bench radios sit a few meters apart.  This module puts the geometry of one pass of the
PQSAT-8 model between a terminal and its radio: at every frame it takes the slant range
and the elevation of the serving satellite at the current time of the pass and applies

  * the pass window: before rise and after set (minimum elevation of the manifest) no frame
    passes in either direction
  * the one way propagation delay  range / c
  * frame loss from the link margin at that range for the radio profile of the manifest
    (SF9, the setting of the bench radios): P(loss) = 1 / (1 + exp(k * margin)), a steep
    curve around 0 dB like the LoRa demodulator threshold; k = 2 per dB by default

Everything else (air time, half duplex turn around, the satellite's processing) is the real
hardware.  The conditions are applied at the terminal side in software, on send and on
receive, and every frame the model removed is counted, so a run reports what the radio lost
and what the model removed separately.

    model = PassModel(site="user", choose="high")          one pass of the day
    link  = ModelledLink(SerialLink("COM8"), model)
    model.start()                                          the pass clock starts at rise
"""
import math
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "..", "..", "platform"), os.path.join(HERE, "..", "..", "platform", "linkbudget")):
    if os.path.isdir(_p) and os.path.abspath(_p) not in sys.path:
        sys.path.insert(0, os.path.abspath(_p))

C_KM_S = 299792.458


class PassModel:
    def __init__(self, site="user", choose="high", constellation="pqsat8", t0=None, horizon_s=24 * 3600,
                 k_per_db=2.0, seed=None, start_offset_s=0.0):
        from pqsat_testbed import orbit
        import linkbudget
        self.orbit, self.budget = orbit, linkbudget
        self.m = orbit.load_manifest(constellation)
        if site == "user":
            self.site = orbit.load_manifest("users")["users"][0]
        elif site == "ground":
            self.site = orbit.load_manifest("ground")["ground_stations"][0]
        else:
            self.site = site
        self.sp = (float(self.site["lat"]), float(self.site["lon"]), float(self.site.get("alt_km", 0)))
        self.sync = orbit.Synchronizer(self.m, orbit.load_manifest("ground"), orbit.load_manifest("users"))
        self.profile = self.m.get("radio", {}).get("profile", "SF9")
        # radio setting of an experiment: PQSAT_SF and PQSAT_PTX (dBm) in the environment replace the
        # spreading factor and the transmit power of the link budget (bench: SF9, 14 dBm)
        if os.environ.get("PQSAT_SF"):
            self.profile = "SF" + os.environ["PQSAT_SF"]
        self.ptx_dbm = float(os.environ["PQSAT_PTX"]) if os.environ.get("PQSAT_PTX") else None
        self.min_el = float(self.m.get("min_elevation_deg", 10))
        t0 = 0.0 if t0 is None else t0                      # seconds after the epoch of the manifest
        passes = [p for p in self.sync.passes(self.site, t0, horizon_s) if p["set"]]
        if not passes:
            raise RuntimeError("the model has no pass at this site in the horizon")
        by_el = sorted(passes, key=lambda p: p["max_elevation"])
        if choose == "high":
            self.p = by_el[-1]
        elif choose == "low":
            self.p = by_el[0]
        elif choose == "mid":
            self.p = by_el[len(by_el) // 2]
        else:
            self.p = passes[int(choose) % len(passes)]
        self.all_passes = passes
        self.sat = next(s for s in self.sync.sats if s["name"] == self.p["satellite"])
        self.duration = self.p["set"] - self.p["rise"]
        self.k = k_per_db
        self.rng = random.Random(seed)
        self.offset = start_offset_s
        self._wall0 = None
        self.enabled = False                               # frames pass untouched until start()
        self.stats = dict(sent=0, sent_removed=0, received=0, received_removed=0, outside_window=0)
        self.trace = []

    # ---- clock
    def start(self, offset_s=None):
        if offset_s is not None:
            self.offset = offset_s
        self._wall0 = time.time()
        self.enabled = True
        self.stats = dict(sent=0, sent_removed=0, received=0, received_removed=0, outside_window=0)
        self.trace = []
        return self

    def stop(self):
        self.enabled = False
        return self

    def tau(self):
        """Seconds since rise of the pass."""
        return self.offset + (time.time() - self._wall0 if self._wall0 else 0.0)

    # ---- geometry
    def state(self, tau=None):
        tau = self.tau() if tau is None else tau
        pos = self.orbit.propagate(self.m, self.sat, self.p["rise"] + tau)
        d = self.orbit.distance_km(pos, self.sp)
        el = self.orbit.elevation_deg(pos, self.sp)
        margin = float(self.budget.margin_db(d, self.profile) if self.ptx_dbm is None
                       else self.budget.margin_db(d, self.profile, p_tx_dbm=self.ptx_dbm))
        # Doppler on the live carrier: the range rate from a one second finite difference of the
        # slant range, turned into a frequency shift at the uplink carrier.  The LoRa demodulator
        # tolerates a shift up to about a quarter of the bandwidth before the symbol error rises;
        # beyond that the model charges an extra loss, so Doppler is applied to the run, not only
        # reported.  At 1414 km it stays inside the tolerance, as the link budget note says.
        d1 = self.orbit.distance_km(self.orbit.propagate(self.m, self.sat, self.p["rise"] + tau + 1.0), self.sp)
        range_rate_kms = d1 - d                                   # km per second, positive when receding
        f_hz = self.m.get("radio", {}).get("frequency_mhz", 868.0) * 1e6
        doppler_hz = -range_rate_kms * 1000.0 / C_KM_S / 1000.0 * f_hz
        bw_hz = self.m.get("radio", {}).get("bandwidth_khz", 125) * 1e3
        tol_hz = 0.25 * bw_hz
        doppler_penalty = max(0.0, (abs(doppler_hz) - tol_hz) / tol_hz) * 3.0   # dB once the shift passes the tolerance
        eff_margin = margin - doppler_penalty
        visible = 0.0 <= tau <= self.duration and el > self.min_el
        p_loss = 1.0 if not visible else 1.0 / (1.0 + math.exp(self.k * eff_margin))
        return dict(tau=round(tau, 1), range_km=round(d, 1), elevation_deg=round(el, 1), margin_db=round(margin, 2),
                    doppler_hz=round(doppler_hz), doppler_penalty_db=round(doppler_penalty, 2),
                    delay_ms=round(d / C_KM_S * 1000, 2), visible=visible, p_loss=round(p_loss, 4))

    def usable_window(self, p_max=0.1, step=5.0):
        """Part of the pass in which the modelled frame loss stays below p_max: (start, end, seconds)."""
        ok = [t for t in [i * step for i in range(int(self.duration / step) + 1)] if self.state(t)["p_loss"] <= p_max]
        return (ok[0], ok[-1], ok[-1] - ok[0]) if ok else (None, None, 0.0)

    def describe(self):
        s0, s1, w = self.usable_window()
        mid = self.state(self.duration / 2)
        rise = self.state(1)
        return dict(satellite=self.p["satellite"], max_elevation_deg=self.p["max_elevation"], pass_seconds=round(self.duration, 0),
                    profile=self.profile, ptx_dbm=self.ptx_dbm if self.ptx_dbm is not None else self.budget.P_TX_DBM, range_km_at_rise=rise["range_km"], range_km_at_peak=mid["range_km"],
                    margin_db_at_rise=rise["margin_db"], margin_db_at_peak=mid["margin_db"],
                    doppler_hz_at_rise=rise["doppler_hz"], doppler_hz_at_peak=mid["doppler_hz"],
                    usable_from_s=s0, usable_to_s=s1, usable_seconds=w, start_offset_s=self.offset)

    def passes_frame(self, direction):
        """Apply the model to one frame.  Returns (kept, one way delay in seconds)."""
        if not self.enabled:
            return True, 0.0
        s = self.state()
        key = "sent" if direction == "up" else "received"
        self.stats[key] += 1
        if not s["visible"]:
            self.stats["outside_window"] += 1
            self.stats[key + "_removed"] += 1
            return False, 0.0
        if self.rng.random() < s["p_loss"]:
            self.stats[key + "_removed"] += 1
            return False, s["delay_ms"] / 1000.0
        if not self.trace or s["tau"] - self.trace[-1]["tau"] >= 30:
            self.trace.append(s)
        return True, s["delay_ms"] / 1000.0


class ModelledLink:
    """A radio link (SerialLink or the emulator's link) seen through a PassModel."""

    def __init__(self, link, model):
        self.link, self.model = link, model

    def __getattr__(self, name):
        return getattr(self.link, name)

    def send(self, frame):
        kept, delay = self.model.passes_frame("up")
        if not kept:
            # the radio still transmits (air time is spent) but the frame does not arrive:
            # one bit of the frame check is spoiled so the satellite's receiver discards it
            bad = bytearray(frame)
            bad[-1] ^= 0xFF
            bad[len(bad) // 2] ^= 0xFF
            return self.link.send(bytes(bad))
        time.sleep(delay)
        return self.link.send(frame)

    def recv(self, timeout):
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                return None
            r = self.link.recv(left)
            if r is None:
                return None
            kept, delay = self.model.passes_frame("down")
            if kept:
                time.sleep(delay)
                return r


if __name__ == "__main__":
    for choose in ("high", "mid", "low"):
        m = PassModel(choose=choose)
        print(choose, m.describe())
    m = PassModel()
    print(len(m.all_passes), "passes in 24 h at", m.site["name"])
    for t in range(0, int(m.duration) + 1, 60):
        print(m.state(t))

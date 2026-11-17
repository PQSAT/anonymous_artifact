"""Orbit layer: the constellation observer and synchronizer of the platform.

Observer: constellation, ground station and user manifests (JSON), kept in the manifests
directory and in the database.  Synchronizer: for every time slot, the position of every
satellite, the visibility of every ground station and user, the inter satellite links that
exist, their propagation delays, the pass schedule, and the link margin from the link budget
module.  The orchestrator and the dashboard read the slot state; nothing here touches a
radio or a process.

Propagation: circular orbits, Kepler with J2 nodal regression, which is what a Walker
constellation needs at the slot resolution of the testbed (1 s) and over a day.  Skyfield or
SGP4 from TLEs can replace `propagate` without changing anything else (set
`PQSAT_PROPAGATOR=sgp4` once the sgp4 package is installed and TLEs are given per satellite).

Manifests (see manifests/pqsat8.json):
    {"name": "PQSAT-8", "walker": {"satellites": 8, "planes": 1, "phasing": 0},
     "altitude_km": 1200, "inclination_deg": 87.9, "raan0_deg": -100, "epoch": "2026-12-12T00:00:00Z",
     "isl": {"topology": "ring"}, "radio": {"profile": "SF11"}, "min_elevation_deg": 10,
     "satellites": [{"name": "SAT-1", "scid": 257, "plane": 0, "slot": 0, "uplink_mhz": 868.1, "downlink_mhz": 869.525, "runs_on": "emulator"}, ...]}
"""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

RE_KM = 6371.0088
MU = 398600.4418          # km^3 s^-2
J2 = 1.08262668e-3
OMEGA_E = 7.2921159e-5    # rad/s, Earth rotation
C_KM_S = 299792.458

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFESTS = os.path.join(HERE, "manifests")                    # shipped templates (read only)
WORK = os.environ.get("PQSAT_MANIFESTS", os.path.join(os.getcwd(), "manifests"))   # the live copies the registry edits


# ----------------------------------------------------------------------------- manifests

def load_manifest(name_or_path: str) -> dict:
    """The live copy in the working directory wins over the shipped template."""
    cands = [name_or_path, os.path.join(WORK, name_or_path + ".json"), os.path.join(MANIFESTS, name_or_path + ".json")]
    p = next((c for c in cands if os.path.isfile(c)), None)
    if p is None:
        raise FileNotFoundError(f"manifest {name_or_path} not found in {WORK} or {MANIFESTS}")
    with open(p) as f:
        return json.load(f)


def save_manifest(m: dict, name: str) -> str:
    os.makedirs(WORK, exist_ok=True)
    p = os.path.join(WORK, name + ".json")
    with open(p, "w") as f:
        json.dump(m, f, indent=1)
    return p


def walker_satellites(m: dict) -> List[dict]:
    """Expand a Walker description into one record per satellite, keeping any explicit
    records already present (added through the registry) and filling the rest."""
    w = m.get("walker", {})
    n, p, f = int(w.get("satellites", 8)), int(w.get("planes", 1)), int(w.get("phasing", 0))
    per = n // p
    sats = list(m.get("satellites", []))
    have = {(s["plane"], s["slot"]) for s in sats if "plane" in s and "slot" in s}
    k = 0
    for plane in range(p if not sats else 0):          # fill from the Walker numbers only when no explicit list exists
        for slot in range(per):
            k += 1
            if (plane, slot) in have:
                continue
            sats.append(dict(name=f"SAT-{k}", scid=0x100 + k, plane=plane, slot=slot,
                             uplink_mhz=868.1 + 0.2 * (k - 1), downlink_mhz=869.525 if k == 1 else 868.5 + 0.2 * (k - 2),
                             runs_on="emulator"))
    sats.sort(key=lambda s: (s["plane"], s["slot"]))
    # rank within the plane: satellites are spread evenly by rank, so a gap left by a revoked
    # node closes and a node added through the registry takes its share of the ring
    for plane in {s["plane"] for s in sats}:
        ps = [s for s in sats if s["plane"] == plane]
        for i, s in enumerate(ps):
            s["_rank"], s["_per"] = i, len(ps)
            s.pop("_el", None)
    m["satellites"] = sats
    return sats


# ----------------------------------------------------------------------------- geometry

def _orbit_elements(m: dict, sat: dict) -> dict:
    w = m.get("walker", {})
    n, p, f = int(w.get("satellites", 8)), int(w.get("planes", 1)), int(w.get("phasing", 0))
    per = n // p
    a = RE_KM + float(m.get("altitude_km", 1200))
    inc = math.radians(float(m.get("inclination_deg", 87.9)))
    raan = math.radians(float(m.get("raan0_deg", 0))) + 2 * math.pi * sat["plane"] / p * float(m.get("raan_spread", 1.0))
    rank, per_plane = sat.get("_rank", sat["slot"]), sat.get("_per", per)
    u0 = 2 * math.pi * (rank / per_plane + f * sat["plane"] / n)
    n_mean = math.sqrt(MU / a ** 3)
    # J2 secular rates (circular orbit)
    k = 1.5 * J2 * (RE_KM / a) ** 2 * n_mean
    raan_dot = -k * math.cos(inc)
    u_dot = n_mean + k * (1 - 1.5 * math.sin(inc) ** 2) + k * (2 - 2.5 * math.sin(inc) ** 2)
    return dict(a=a, inc=inc, raan=raan, u0=u0, raan_dot=raan_dot, u_dot=u_dot, period=2 * math.pi / n_mean)


def propagate(m: dict, sat: dict, t: float) -> Tuple[float, float, float]:
    """Geodetic position (lat deg, lon deg, alt km) of one satellite at t seconds after the
    manifest epoch.  Circular orbit with J2 regression; Earth rotation applied."""
    el = sat.get("_el") or _orbit_elements(m, sat)
    sat["_el"] = el
    u = el["u0"] + el["u_dot"] * t
    raan = el["raan"] + el["raan_dot"] * t
    x = math.cos(u); y = math.sin(u)
    # orbital plane to ECI
    xi = x * math.cos(raan) - y * math.cos(el["inc"]) * math.sin(raan)
    yi = x * math.sin(raan) + y * math.cos(el["inc"]) * math.cos(raan)
    zi = y * math.sin(el["inc"])
    lat = math.degrees(math.asin(zi))
    lon = math.degrees(math.atan2(yi, xi) - OMEGA_E * t)
    lon = ((lon + 540) % 360) - 180
    return lat, lon, el["a"] - RE_KM


def ecef(lat: float, lon: float, alt_km: float) -> Tuple[float, float, float]:
    r = RE_KM + alt_km
    la, lo = math.radians(lat), math.radians(lon)
    return r * math.cos(la) * math.cos(lo), r * math.cos(la) * math.sin(lo), r * math.sin(la)


def distance_km(a: Tuple[float, float, float], b: Tuple[float, float, float]) -> float:
    return math.dist(ecef(*a), ecef(*b))


def elevation_deg(sat_pos: Tuple[float, float, float], site: Tuple[float, float, float]) -> float:
    """Elevation of the satellite as seen from the site (lat, lon, alt)."""
    sx, sy, sz = ecef(*sat_pos)
    gx, gy, gz = ecef(*site)
    dx, dy, dz = sx - gx, sy - gy, sz - gz
    rng = math.sqrt(dx * dx + dy * dy + dz * dz)
    gn = math.sqrt(gx * gx + gy * gy + gz * gz)
    cos_z = (dx * gx + dy * gy + dz * gz) / (rng * gn)
    return math.degrees(math.asin(max(-1.0, min(1.0, cos_z))))


def coverage_angle_deg(alt_km: float, min_el_deg: float) -> float:
    r = RE_KM + alt_km
    e = math.radians(min_el_deg)
    return math.degrees(math.acos(RE_KM / r * math.cos(e)) - e)


# ----------------------------------------------------------------------------- synchronizer

@dataclass
class Link:
    a: str                 # node name
    b: str
    kind: str              # isl | feeder | user
    delay_ms: float
    distance_km: float
    elevation_deg: Optional[float] = None
    margin_db: Optional[float] = None
    profile: Optional[str] = None


@dataclass
class SlotState:
    t: float
    positions: Dict[str, Tuple[float, float, float]]
    links: List[Link]
    serving: Dict[str, Optional[str]]      # user name -> satellite name
    feeder: Dict[str, Optional[str]]       # ground station name -> satellite name
    elevations: Dict[str, Dict[str, float]] = field(default_factory=dict)


class Synchronizer:
    """Computes the slot state of a constellation with its ground stations and users."""

    def __init__(self, constellation: dict, ground: dict, users: dict):
        self.m = constellation
        self.sats = walker_satellites(constellation)
        self.ground = ground.get("ground_stations", ground if isinstance(ground, list) else [])
        self.users = users.get("users", users if isinstance(users, list) else [])
        self.min_el = float(constellation.get("min_elevation_deg", 10))
        self.policy = constellation.get("gsl_policy", "longest_remaining")   # or "highest_elevation"
        self._serving: Dict[str, Optional[str]] = {}
        self._feeder: Dict[str, Optional[str]] = {}
        self.events: List[dict] = []
        self._budget = None
        try:                                              # optional: link margin from the link budget module
            import importlib, sys
            for p in (os.path.join(HERE, "..", "..", "linkbudget"), os.path.join(HERE, "..", "linkbudget")):
                if os.path.isdir(p) and p not in sys.path:
                    sys.path.insert(0, p)
            self._budget = importlib.import_module("linkbudget")
        except Exception:
            self._budget = None

    # positions
    def positions(self, t: float) -> Dict[str, Tuple[float, float, float]]:
        return {s["name"]: propagate(self.m, s, t) for s in self.sats}

    def period_s(self) -> float:
        return _orbit_elements(self.m, self.sats[0])["period"]

    # inter satellite links
    def isl_pairs(self) -> List[Tuple[str, str]]:
        topo = self.m.get("isl", {}).get("topology", "ring")
        names = [s["name"] for s in self.sats]
        w = self.m.get("walker", {})
        n, p = len(names), int(w.get("planes", 1))
        per = n // p
        pairs = []
        if topo in ("ring", "grid", "+grid"):
            for plane in range(p):
                for i in range(per):
                    a = self.sats[plane * per + i]["name"]
                    b = self.sats[plane * per + (i + 1) % per]["name"]
                    if a != b:
                        pairs.append((a, b))
        if topo in ("grid", "+grid") and p > 1:
            for plane in range(p):
                for i in range(per):
                    a = self.sats[plane * per + i]["name"]
                    b = self.sats[((plane + 1) % p) * per + i]["name"]
                    pairs.append((a, b))
        explicit = self.m.get("isl", {}).get("pairs")
        if explicit:
            pairs = [tuple(x) for x in explicit]
        return pairs

    def margin(self, distance_km: float, profile: str) -> Optional[float]:
        if self._budget is None:
            return None
        try:
            if hasattr(self._budget, "margin_db"):
                return float(self._budget.margin_db(distance_km, profile))
        except Exception:
            return None
        return None

    def profile_for(self, distance_km: float, default: str) -> str:
        """Adaptive spreading factor: the lowest one that closes the link with 3 dB at this
        slant range (LoRa ADR), or the manifest's profile when the budget module is absent
        or the manifest fixes it ("adaptive_sf": false)."""
        if not self.m.get("radio", {}).get("adaptive_sf", True) or self._budget is None or not hasattr(self._budget, "required_sf"):
            return default
        sf = self._budget.required_sf(distance_km, 3.0)
        return f"SF{sf}" if sf else "SF12"

    def slot(self, t: float) -> SlotState:
        pos = self.positions(t)
        links: List[Link] = []
        elev: Dict[str, Dict[str, float]] = {}
        profile = self.m.get("radio", {}).get("profile", "SF9")
        for a, b in self.isl_pairs():
            d = distance_km(pos[a], pos[b])
            links.append(Link(a, b, "isl", d / C_KM_S * 1000, d))
        sites = [("gs", g) for g in self.ground] + [("user", u) for u in self.users]
        for kind, site in sites:
            sp = (float(site["lat"]), float(site["lon"]), float(site.get("alt_km", 0)))
            elev[site["name"]] = {}
            for s in self.sats:
                e = elevation_deg(pos[s["name"]], sp)
                elev[site["name"]][s["name"]] = e
        # serving and feeder selection with hysteresis: keep the current one while visible
        serving, feeder = {}, {}
        for kind, site in sites:
            name = site["name"]
            vis = {s: e for s, e in elev[name].items() if e > self.min_el}
            cur = (self._serving if kind == "user" else self._feeder).get(name)
            sp_ = (float(site["lat"]), float(site["lon"]), float(site.get("alt_km", 0)))
            if cur in vis and len(vis) > 1 and kind == "user":
                # another satellite is in view while the serving one is still up: hand over
                # now, while the overlap lasts (the orchestrator measures whether it sufficed)
                others = {k: v for k, v in vis.items() if k != cur}
                nxt = self._choose(others, pos, site, t)
                left = self.time_to_set(cur, sp_, t)
                if self.time_to_set(nxt, sp_, t) > left:
                    self.events.append(dict(t=t, kind="handover", site=name, frm=cur, to=nxt, overlap_s=left))
                    chosen = nxt
                else:
                    chosen = cur
            elif cur in vis:
                chosen = cur
            elif vis:
                chosen = self._choose(vis, pos, site, t)
                if cur is not None:
                    self.events.append(dict(t=t, kind="handover" if kind == "user" else "feeder_change", site=name, frm=cur, to=chosen))
                else:
                    self.events.append(dict(t=t, kind="acquired", site=name, to=chosen))
            else:
                chosen = None
                if cur is not None:
                    self.events.append(dict(t=t, kind="lost", site=name, frm=cur))
            (serving if kind == "user" else feeder)[name] = chosen
            if chosen:
                sp = (float(site["lat"]), float(site["lon"]), float(site.get("alt_km", 0)))
                d = distance_km(pos[chosen], sp)
                prof = self.profile_for(d, profile)
                links.append(Link(name, chosen, "user" if kind == "user" else "feeder", d / C_KM_S * 1000, d,
                                  elev[name][chosen], self.margin(d, prof), prof))
        self._serving, self._feeder = serving, feeder
        return SlotState(t, pos, links, serving, feeder, elev)

    def _choose(self, vis: Dict[str, float], pos, site, t) -> str:
        if self.policy == "highest_elevation":
            return max(vis, key=vis.get)
        # longest remaining visibility: look ahead
        best, best_left = None, -1
        sp = (float(site["lat"]), float(site["lon"]), float(site.get("alt_km", 0)))
        for s in vis:
            left = self.time_to_set(s, sp, t)
            if left > best_left:
                best, best_left = s, left
        return best

    def time_to_set(self, sat_name: str, site: Tuple[float, float, float], t: float, step: float = 10, horizon: float = 7200) -> float:
        sat = next(s for s in self.sats if s["name"] == sat_name)
        for dt in range(0, int(horizon), int(step)):
            if elevation_deg(propagate(self.m, sat, t + dt), site) <= self.min_el:
                return float(dt)
        return float(horizon)

    def passes(self, site: dict, t0: float, horizon: float = 2 * 3600, step: float = 15) -> List[dict]:
        """Rise, set and maximum elevation of every pass at a site within the horizon."""
        sp = (float(site["lat"]), float(site["lon"]), float(site.get("alt_km", 0)))
        out = []
        for s in self.sats:
            up, rise, maxel = False, None, 0.0
            dt = 0.0
            while dt <= horizon:
                e = elevation_deg(propagate(self.m, s, t0 + dt), sp)
                if not up and e > self.min_el:
                    up, rise, maxel = True, dt, e
                elif up:
                    maxel = max(maxel, e)
                    if e <= self.min_el:
                        out.append(dict(satellite=s["name"], scid=s["scid"], rise=t0 + rise, set=t0 + dt, max_elevation=round(maxel, 1)))
                        up = False
                dt += step
            if up:
                out.append(dict(satellite=s["name"], scid=s["scid"], rise=t0 + rise, set=None, max_elevation=round(maxel, 1)))
        out.sort(key=lambda p: p["rise"])
        return out

    def schedule(self, t0: float, duration: float, step: float) -> List[dict]:
        """Slot by slot state as plain dicts (what /api/env/schedule returns and what the
        orchestrator replays)."""
        rows = []
        t = t0
        while t <= t0 + duration:
            s = self.slot(t)
            rows.append(dict(t=t, positions=s.positions, serving=s.serving, feeder=s.feeder,
                             links=[l.__dict__ for l in s.links]))
            t += step
        return rows

    def summary(self) -> dict:
        return dict(name=self.m.get("name"), satellites=len(self.sats), planes=self.m.get("walker", {}).get("planes", 1),
                    altitude_km=self.m.get("altitude_km"), inclination_deg=self.m.get("inclination_deg"),
                    isl=self.m.get("isl", {}).get("topology", "ring"), period_s=round(self.period_s(), 1),
                    coverage_deg=round(coverage_angle_deg(float(self.m.get("altitude_km", 1200)), self.min_el), 1),
                    ground_stations=[g["name"] for g in self.ground], users=[u["name"] for u in self.users])


# ----------------------------------------------------------------------------- orchestration plan

def handover_plan(sync: Synchronizer, user: dict, t0: float, horizon: float = 7200, handover_s: float = 18.7, handshake_s: float = 371.0) -> List[dict]:
    """For each pass transition at a user: the overlap between the serving and the next
    satellite, and whether the pre arranged handover and a new handshake fit in it.  This
    is the table the dashboard shows and the orchestrator uses to fire handovers."""
    ps = sync.passes(user, t0, horizon)
    plan = []
    for i in range(len(ps) - 1):
        cur, nxt = ps[i], ps[i + 1]
        if cur["set"] is None:
            continue
        overlap = max(0.0, cur["set"] - nxt["rise"])
        plan.append(dict(frm=cur["satellite"], to=nxt["satellite"], at=max(nxt["rise"], cur["set"] - max(handover_s * 2, 30)),
                         overlap_s=round(overlap, 1), prearranged_fits=overlap >= handover_s, handshake_fits=overlap >= handshake_s))
    return plan


if __name__ == "__main__":
    import argparse, time
    ap = argparse.ArgumentParser(description="print the pass schedule of a constellation at a site")
    ap.add_argument("--constellation", default="pqsat8")
    ap.add_argument("--ground", default="ground")
    ap.add_argument("--users", default="users")
    ap.add_argument("--hours", type=float, default=3)
    a = ap.parse_args()
    sy = Synchronizer(load_manifest(a.constellation), load_manifest(a.ground), load_manifest(a.users))
    print(json.dumps(sy.summary(), indent=1))
    for site in sy.ground + sy.users:
        print(f"\npasses at {site['name']} over {a.hours} h")
        for p in sy.passes(site, 0, a.hours * 3600):
            print(f"  {p['satellite']:6s} rise {p['rise']:8.0f} s  set {p['set'] if p['set'] is None else round(p['set']):>8}  max el {p['max_elevation']:5.1f}")
    for u in sy.users:
        print("\nhandover plan at", u["name"])
        for h in handover_plan(sy, u, 0, a.hours * 3600):
            print(f"  {h['frm']} -> {h['to']} at {h['at']:.0f} s  overlap {h['overlap_s']} s  pre arranged fits {h['prearranged_fits']}  handshake fits {h['handshake_fits']}")

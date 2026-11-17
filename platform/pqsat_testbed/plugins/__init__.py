"""Plug in interfaces.  A researcher adds a module under this package (or anywhere, and
registers it) implementing one of four base classes; the platform discovers it by name.

    Protocol    an authentication or key establishment protocol: the user, ground and
                satellite roles and the message flow between them.  It is carried over the
                real link by the platform; it never sees frames.
    LinkModel   the channel of the emulator: loss, delay, half duplex, ISL delay.
    Experiment  what to run and what to measure: handshakes, traffic, handover, attacks.
    Attack      an adversary action from the adversary terminal.

Registration: subclass and set `name`; modules in this package are imported at start.
"""
import importlib
import pkgutil

PROTOCOLS, LINKS, EXPERIMENTS, ATTACKS = {}, {}, {}, {}


class _Registered:
    name = None
    registry = None

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        if cls.name and cls.registry is not None:
            cls.registry[cls.name] = cls


class Protocol(_Registered):
    """A protocol plug in.

    satellite_role: "flight" when the satellite side is the flight C module in the
    satellite core (our protocol), "python" when the plug in supplies a Python satellite
    session and the satellite core hands authentication messages to it (SAT_AUTH_EXTERNAL).

    run(platform, nodes, **options) drives one handshake with the terminals in
    `nodes` (ue, gs, sats) and returns a record in the common shape (see
    handshake_runner.run_handshake): ok, seconds, octets_total, uplink_segments,
    uplink_retransmissions, downlink_frames, downlink_lost, downlink_naks,
    downlink_repaired, messages[], sk_user, sk_ground, and anything else it wants kept.
    """
    registry = PROTOCOLS
    satellite_role = "flight"
    description = ""

    def run(self, platform, nodes, **options):
        raise NotImplementedError

    def satellite_session(self, sat_name):
        """Python satellite role for satellite_role == "python": an object with
        handle(src, message) -> list of (dst, message) and session_key() -> bytes or None."""
        raise NotImplementedError


class LinkModel(_Registered):
    registry = LINKS
    description = ""
    loss = 0.0            # frame loss probability on each radio link
    half_duplex = True    # satellite radio deaf while transmitting (measured on the hardware)
    isl_delay_ms = 12.0   # inter satellite link delay per frame
    tx_pace_pct = None    # satellite transmit pacing, percent of air time (None: default)
    rx_window_ms = None   # satellite receive window after a segment ack (None: default)

    def env(self):
        e = {}
        if self.tx_pace_pct is not None:
            e["SAT_TX_PACE_PCT"] = str(self.tx_pace_pct)
        if self.rx_window_ms is not None:
            e["SAT_RX_WINDOW_MS"] = str(self.rx_window_ms)
        if not self.half_duplex:
            e["SIM_SAT_HALF_DUPLEX"] = "0"
        return e


class Experiment(_Registered):
    registry = EXPERIMENTS
    description = ""
    needs_nodes = True   # False for experiments that only read the database (prediction, statistics)

    def run(self, platform, nodes, db, run_id, live, **params):
        """Return a summary dict; write records through db; call live(event) for the stream."""
        raise NotImplementedError


class Attack(_Registered):
    registry = ATTACKS
    description = ""

    def run(self, platform, nodes, adversary, **params):
        """Perform the attack with the adversary terminal; return dict(name, accepted_by_link,
        rejected_by, evidence)."""
        raise NotImplementedError


def load_all():
    import pqsat_testbed.plugins as pkg
    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name.startswith("_"):
            continue
        importlib.import_module(f"pqsat_testbed.plugins.{m.name}")
    import pqsat_testbed.experiments as ex
    for m in pkgutil.iter_modules(ex.__path__):
        importlib.import_module(f"pqsat_testbed.experiments.{m.name}")


def catalogue():
    load_all()
    def rows(reg):
        return {k: dict(description=v.description, satellite_role=getattr(v, "satellite_role", None))
                for k, v in reg.items()}
    return dict(protocols=rows(PROTOCOLS), links=rows(LINKS), experiments=rows(EXPERIMENTS), attacks=rows(ATTACKS))

"""Simulated RF channel for testing: the real satellite core (satsim, compiled from ccsds_core.h)
plus half-duplex fake modems that behave like modem.ino (same send/recv interface as SerialLink)."""
import queue
import random
import subprocess
import sys
import threading
import time
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "gs", "lib"))
from ccsds_link import lora_airtime_ms  # noqa: E402


class SimSatellite:
    """One satellite process.  env configures it (SAT_SCID, SAT_ISL_PEER, ...).
    isl_delay_ms models the inter satellite link: propagation plus serialisation
    of one 255 octet frame (default 12 ms: a few hundred km of free space at a
    few Mbit/s).  Frames from this satellite's ISL are delivered to `isl_peer`."""

    def __init__(self, exe, loss=0.0, debug=False, env=None, name="SAT", isl_delay_ms=12.0):
        e = dict(os.environ)
        e.update(env or {})
        self.p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, env=e)
        self.name = name
        self.isl_peer = None                     # single neighbour (index 0), kept for the two satellite tests
        self.isl_peers = {}                      # peer index -> SimSatellite (chain)
        self.isl_delay = isl_delay_ms / 1000
        self.isl_frames_tx = 0
        self.isl_bytes_tx = 0
        self.isl_log = []                        # (t, frame) every ISL frame this satellite sent
        self.isl_q = queue.Queue()               # frames to the neighbour, delivered in order after the delay
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.modems = []
        self.loss, self.debug = loss, debug
        self.log = []
        self.log_t = []                          # time.time() of each log line, same index as log
        self.auth_rx = []                        # (t, src, message) when SAT_AUTH_EXTERNAL=1: the harness runs the satellite role
        self.tx_spans = []                       # satellite transmit intervals (half duplex model)
        self.half_duplex = os.environ.get("SIM_SAT_HALF_DUPLEX", "1") != "0"
        self.uplink_collisions = 0
        self._run = True
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._clock, daemon=True).start()
        threading.Thread(target=self._isl_pump, daemon=True).start()

    def now(self):
        return int((time.time() - self.t0) * 1000)

    def write(self, s):
        with self.lock:
            self.p.stdin.write(s + "\n")
            self.p.stdin.flush()

    def _clock(self):
        while self._run:
            self.write(f"C,{self.now()}")
            time.sleep(0.02)

    def _reader(self):
        for line in self.p.stdout:
            line = line.strip()
            if line.startswith("TX,"):
                _, _, hx = line.split(",", 2)
                frame = bytes.fromhex(hx)
                air = lora_airtime_ms(len(frame)) / 1000
                t_start = time.time()
                with self.lock:
                    self.tx_spans.append((t_start, t_start + air))
                    self.tx_spans = self.tx_spans[-50:]
                time.sleep(air)                      # satellite TX board blocks while transmitting
                for m in self.modems:
                    m.deliver(frame, air)
            elif line.startswith("ISL"):
                tag, _, hx = line.split(",", 2)
                idx = int(tag[3:] or "0")
                frame = bytes.fromhex(hx)
                self.isl_frames_tx += 1
                self.isl_bytes_tx += len(frame)
                self.isl_log.append((time.time(), frame))
                self.isl_q.put((time.time() + self.isl_delay, idx, frame))
            elif line.startswith("AUTH,"):
                _, src, hx = line.split(",", 2)
                self.auth_rx.append((time.time(), int(src, 16), bytes.fromhex(hx)))
            elif line.startswith("LOG,"):
                self.log_t.append(time.time())
                self.log.append(line[4:])
                if self.debug:
                    print(f"   {self.name}:", line[4:])

    def _isl_pump(self):
        """The ISL is an ordered link: frames reach the neighbour in the order sent."""
        while self._run:
            try:
                due, idx, frame = self.isl_q.get(timeout=0.5)
            except queue.Empty:
                continue
            d = due - time.time()
            if d > 0:
                time.sleep(d)
            peer = self.isl_peers.get(idx, self.isl_peer if idx == 0 else None)
            if peer is not None:
                peer.isl_rx(frame)

    def send_auth(self, dst, msg):
        """External satellite role: send an authentication message down to terminal dst."""
        self.write(f"A,{dst:04X},{msg.hex().upper()}")

    def sdls_start(self, sk):
        """External satellite role: key SDLS from the session key (as the C module does at MSG8)."""
        self.write(f"K,{bytes(sk).hex().upper()}")

    def isl_rx(self, frame):
        if self._run:
            self.write(f"I,{frame.hex().upper()}")

    def uplink(self, frame):
        """frame has just finished arriving: it occupied the channel for its air time.
        The satellite radio is half duplex, so if the satellite transmitted at any
        moment of that interval the frame is lost (as measured on the hardware)."""
        if random.random() < self.loss:
            return
        end = time.time()
        start = end - lora_airtime_ms(len(frame)) / 1000
        if self.half_duplex and any(a < end and b > start for a, b in list(self.tx_spans)):
            self.uplink_collisions += 1
            return
        self.write(f"R,-40,9,{self.now()},{frame.hex().upper()}")

    def close(self):
        self._run = False
        self.p.stdin.close()
        self.p.wait()


class SimModem:
    """Half-duplex like the real modem: frames arriving while it transmits are lost."""

    def __init__(self, sat, name, loss=0.0):
        self.sat, self.name, self.loss = sat, name, loss
        self.rx = queue.Queue()
        self.busy_until = 0.0
        self.missed = 0
        sat.modems.append(self)

    def deliver(self, frame, air):
        start = time.time() - air
        if start < self.busy_until or random.random() < self.loss:
            self.missed += 1
            return
        self.rx.put((-40.0, 9.0, frame))

    def send(self, frame):
        air = lora_airtime_ms(len(frame)) / 1000
        self.busy_until = time.time() + air + 0.01
        time.sleep(air)
        self.sat.uplink(frame)
        return f"SENT,{len(frame)},0,{int(air * 1000)}"

    def recv(self, timeout):
        try:
            return self.rx.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        pass

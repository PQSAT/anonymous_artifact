#!/usr/bin/env python3
"""
sat_bridge.py  -  connects Satellite 1 (cFS on the Versal) to its two radios.

    SAT-1 RX T-Beam --USB--> laptop --COM (UART0)--> Versal A72-0 (satellite software)
    SAT-1 TX T-Beam <--USB-- laptop <--COM (UART0)-- Versal A72-0

The bridge only moves frames. All satellite logic (CCSDS frames, COP-1, commands, relay)
runs on the Versal. On a real satellite the radios would be wired straight to the
on-board computer; here the laptop stands in for that wiring.

Both radio T-Beams run the normal modem.ino firmware. The bridge sets their frequencies:
    TX radio: transmits on 869.525 MHz (downlink)
    RX radio: listens on 868.1 MHz (uplink)

Usage:
    python sat_bridge.py --list
    python sat_bridge.py --versal COM7 --radio COM6                  one satellite, one radio
    python sat_bridge.py --versal COM7 --tx COM5 --rx COM6           one satellite, two radios
    python sat_bridge.py --versal COM7 --radio COM6 --radio2 COM8    two satellites (constellation)

Constellation mode: the Versal runs SAT-1 (cpu1) and SAT-2 (cpu2) behind sat_mux,
which shares the one UART; lines for SAT-2 carry the prefix "2:" both ways.  SAT-2's
radio is the fourth T-Beam on its own frequency pair (SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ),
so the user tunes to SAT-2 and the ground to SAT-1.

RF inter satellite link (four more T-Beams, 433 MHz, the same modem.ino):
    python sat_bridge.py --versal COM7 --radio COM6 --radio2 COM8 \
                         --isl1-tx COM10 --isl1-rx COM11 --isl2-tx COM12 --isl2-rx COM13
    SAT-1 transmits to SAT-2 on 433.575 MHz (isl1-tx to isl2-rx) and SAT-2 to SAT-1 on
    434.375 MHz (isl2-tx to isl1-rx).  Two radios per satellite on two frequencies, so the
    link is full duplex.  The flight software must run with SAT_ISL_RF=1.
    python sat_bridge.py --isl-selftest --isl1-tx COM10 --isl1-rx COM11 --isl2-tx COM12 --isl2-rx COM13
Needs: pyserial (pip install pyserial)
"""
import argparse
import os
import csv
import datetime
import queue
import sys
import threading
import time

UPLINK_MHZ = 868.100
DOWNLINK_MHZ = 869.525
SAT2_UPLINK_MHZ = 868.300       # SAT-2 channel pair: 125 kHz channels that do not overlap SAT-1's
SAT2_DOWNLINK_MHZ = 868.500
ISL_12_MHZ = 433.575            # SAT-1 to SAT-2
ISL_21_MHZ = 433.175            # SAT-2 to SAT-1. Not 434.375: twice that is 868.75 MHz, next to the 868.5 MHz downlink of
                                # SAT-2, and the ISL receiver of SAT-1 then decodes downlink frames and misses ISL frames



def write_paced(port, data, chunk=32, gap=0.005):
    """Write a long line to a T-Beam in small pieces.  The ESP32-S3 USB serial
    input buffer is 256 bytes and overflows silently, so a 255 octet frame
    (a 514 character line) written in one go arrives truncated or corrupted."""
    for i in range(0, len(data), chunk):
        port.write(data[i:i + chunk])
        port.flush()
        time.sleep(gap)


def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


class IslRadios:
    """The two ISL radios of one satellite: one only transmits, one only receives.
    Frames from the flight software (ITX lines) are queued and sent one after another;
    frames heard go back to the flight software as I lines."""

    def __init__(self, sat, tx_port, rx_port, tx_mhz, rx_mhz, to_versal, say, log_path=None):
        self.sat, self.txr, self.rxr, self.tx_mhz, self.rx_mhz = sat, tx_port, rx_port, tx_mhz, rx_mhz
        self.single = tx_port is rx_port     # one board does both jobs (half duplex), like the satellite radio
        self.to_versal, self.say = to_versal, say
        self.txq, self.sent = queue.Queue(), queue.Queue()
        self.ok = {"tx": threading.Event(), "rx": threading.Event()}
        self.stats = dict(tx=0, tx_fail=0, rx=0, rx_crc=0)
        self.on_frame = None                 # self test hook
        self._run = True
        self.log = None
        if log_path:
            f = open(log_path, "a", newline="")
            self.log = (f, csv.writer(f))
            if f.tell() == 0:
                self.log[1].writerow(["time", "dir", "sat", "bytes", "scid", "vc", "rssi", "snr", "air_ms", "queue",
                                      "info", "hex"])
                f.flush()                    # both satellites append to this one file

    def csv(self, d, hx, rssi="", snr="", air="", info=""):
        if self.log:
            n = len(hx) // 2
            scid = f"{((int(hx[0:2], 16) & 0x3F) << 4) | (int(hx[2:4], 16) >> 4):03X}" if n > 2 else ""
            vc = (int(hx[2:4], 16) >> 1) & 7 if n > 2 else ""
            self.log[1].writerow([datetime.datetime.now().isoformat(timespec="milliseconds"), d, self.sat, n, scid, vc,
                                  rssi, snr, air, self.txq.qsize(), info, hx])
            self.log[0].flush()

    def send(self, hx):
        self.txq.put(hx)

    def _on_tx_radio(self, s):
        if s.startswith("SENT,"):
            self.sent.put(s)
        elif s.startswith("CFG,OK"):
            self.ok["tx"].set()
        elif s.startswith("MODEM"):
            self.say(f"SAT-{self.sat} ISL TX radio: {s}")

    def _on_rx_radio(self, s):
        if s.startswith("PKT,"):
            _, rssi, snr, hx = s.split(",", 3)
            r, q = int(float(rssi)), int(float(snr))
            self.stats["rx"] += 1
            if self.on_frame:
                self.on_frame(hx, r, q)
            else:
                self.to_versal(f"I,{r},{q},{hx}")
            self.say(f"ISL>{self.sat} {len(hx) // 2:3d} B  RSSI {r}  SNR {q}")
            self.csv("isl_rx", hx, r, q)
        elif s == "CRCERR":
            self.stats["rx_crc"] += 1
            self.say(f"ISL>{self.sat} CRC error")
        elif s.startswith("CFG,OK"):
            self.ok["rx"].set()
        elif s.startswith("MODEM"):
            self.say(f"SAT-{self.sat} ISL RX radio: {s}")

    def _tx_worker(self):
        while self._run:
            try:
                hx = self.txq.get(timeout=0.2)
            except queue.Empty:
                continue
            while not self.sent.empty():
                self.sent.get_nowait()
            try:
                write_paced(self.txr, f"TX,{hx}\n".encode())
            except Exception:
                self.stats["tx_fail"] += 1
                self.say(f"ISL{self.sat}> transmit board does not accept data, frame dropped")
                continue
            try:
                r = self.sent.get(timeout=4.0).split(",")
                ok, air = len(r) >= 3 and r[2] == "0", (r[3] if len(r) > 3 else "?")
            except queue.Empty:
                ok, air = False, "timeout"
            self.stats["tx" if ok else "tx_fail"] += 1
            self.say(f"ISL{self.sat}> {len(hx) // 2:3d} B  {air} ms  queue {self.txq.qsize()}" + ("" if ok else "  FAILED"))
            self.csv("isl_tx", hx, air=air, info="ok" if ok else f"fail {air}")

    def _configure(self, port, key, mhz, label):
        for _ in range(5):
            try:
                port.write(f"CFG,{mhz:.3f},{mhz:.3f}\n".encode())
            except Exception as e:
                self.say(f"WARNING SAT-{self.sat} ISL {label} radio on {getattr(port, 'port', '?')} does not accept data ({e}). "
                         f"The board is on USB but its firmware is not running.")
                return False
            if self.ok[key].wait(1.5):
                self.say(f"SAT-{self.sat} ISL {label} radio ready ({mhz:.3f} MHz)")
                return True
        self.say(f"WARNING SAT-{self.sat} ISL {label} radio did not answer. Is it running modem.ino on the right COM port?")
        return False

    def _on_single_radio(self, s):
        """One board for both directions: SENT and CFG lines are the transmit side,
        PKT and CRCERR lines are the receive side."""
        if s.startswith("CFG,OK"):
            self.ok["tx"].set()
            self.ok["rx"].set()
        elif s.startswith("SENT,") or s.startswith("MODEM"):
            self._on_tx_radio(s)
        else:
            self._on_rx_radio(s)

    def start(self):
        run = lambda: self._run  # noqa: E731
        if self.single:
            threading.Thread(target=Bridge._readlines, args=(self.txr, f"SAT-{self.sat} ISL", self._on_single_radio, run),
                             daemon=True).start()
            ok = False
            for _ in range(5):
                try:
                    self.txr.write(f"CFG,{self.tx_mhz:.3f},{self.rx_mhz:.3f}\n".encode())
                except Exception as e:
                    self.say(f"WARNING SAT-{self.sat} ISL radio on {getattr(self.txr, 'port', '?')} does not accept data ({e})")
                    break
                if self.ok["tx"].wait(1.5):
                    ok = True
                    self.say(f"SAT-{self.sat} ISL radio ready, half duplex on one board "
                             f"(transmit {self.tx_mhz:.3f}, receive {self.rx_mhz:.3f} MHz)")
                    break
            if not ok:
                self.say(f"WARNING SAT-{self.sat} ISL radio did not answer. Is it running modem.ino on the right COM port?")
            threading.Thread(target=self._tx_worker, daemon=True).start()
            return ok
        threading.Thread(target=Bridge._readlines, args=(self.txr, f"SAT-{self.sat} ISL TX", self._on_tx_radio, run),
                         daemon=True).start()
        threading.Thread(target=Bridge._readlines, args=(self.rxr, f"SAT-{self.sat} ISL RX", self._on_rx_radio, run),
                         daemon=True).start()
        ok = self._configure(self.txr, "tx", self.tx_mhz, "TX") & self._configure(self.rxr, "rx", self.rx_mhz, "RX")
        threading.Thread(target=self._tx_worker, daemon=True).start()
        return ok

    def stop(self):
        self._run = False
        if self.log:
            self.log[0].close()


def isl_selftest(i1, i2, frames=20, size=255):
    """Both directions at once, no Versal needed: proves the four ISL radios and full duplex."""
    got = {1: [], 2: []}
    i1.on_frame = lambda hx, r, q: got[1].append((hx.upper(), r, q))
    i2.on_frame = lambda hx, r, q: got[2].append((hx.upper(), r, q))
    if not (i1.start() & i2.start()):
        return 1
    sent = {1: [], 2: []}
    for k in range(frames):
        for sat, isl in ((1, i1), (2, i2)):
            hx = bytes([0x10, 0x16 if sat == 1 else 0x26, k] + [(k * 7 + j + sat) & 0xFF for j in range(size - 3)]).hex().upper()
            sent[sat].append(hx)
            isl.send(hx)
    t0 = time.time()
    while time.time() - t0 < frames * 4 + 20 and (
            i1.stats["tx"] + i1.stats["tx_fail"] < frames or i2.stats["tx"] + i2.stats["tx_fail"] < frames):
        time.sleep(0.2)
    el = time.time() - t0
    time.sleep(1.5)
    ok = True
    for src, dst in ((1, 2), (2, 1)):
        good = [g for g in got[dst] if g[0] in sent[src]]
        rssi = sum(g[1] for g in good) / len(good) if good else float("nan")
        snr = sum(g[2] for g in good) / len(good) if good else float("nan")
        print(f"ISL SAT-{src} to SAT-{dst}: {len(good)} of {frames} frames of {size} octets intact, "
              f"mean RSSI {rssi:.1f} dBm, SNR {snr:.1f} dB")
        ok &= len(good) == frames
    one = frames * 1.72
    print(f"both directions together took {el:.1f} s; one direction alone needs {one:.1f} s of air time: "
          + ("full duplex confirmed" if el < 1.5 * one else "the directions did NOT overlap"))
    print("ISL SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


class Bridge:
    """ports: objects with write(bytes) and readline() -> bytes (b'' on timeout)."""

    def __init__(self, versal, tx_radio, rx_radio, log_path=None, quiet=False, sat=1, writer=None,
                 up_mhz=UPLINK_MHZ, down_mhz=DOWNLINK_MHZ):
        self.v, self.txr, self.rxr = versal, tx_radio, rx_radio
        self.single = tx_radio is rx_radio   # one T-Beam doing both jobs (half duplex)
        self.sat = sat                        # which satellite instance on the Versal this bridge serves
        self.prefix = "" if sat == 1 else f"{sat}:"
        self.writer = writer                  # shared lock for the one UART in constellation mode
        self.up_mhz, self.down_mhz = up_mhz, down_mhz
        self.quiet = quiet
        self.txq = queue.Queue()
        self.sent = queue.Queue()
        self.cfg_ok = {"tx": threading.Event(), "rx": threading.Event()}
        self.pong = threading.Event()
        self.stats = dict(up=0, up_crc=0, down=0, down_fail=0, sat_logs=0)
        self.wlock = threading.Lock()
        self.isl = None                       # IslRadios of this satellite when the ISL is on RF
        self._run = True
        self.log = None
        if log_path:
            f = open(log_path, "a", newline="")
            self.log = (f, csv.writer(f))
            if f.tell() == 0:
                self.log[1].writerow(["time", "dir", "bytes", "rssi", "snr", "info", "hex"])

    # ---------------- helpers ----------------
    def say(self, s):
        if not self.quiet:
            print(f"{ts()}  {s}", flush=True)

    def csv(self, d, n, rssi, snr, info, hx=""):
        if self.log:
            self.log[1].writerow([datetime.datetime.now().isoformat(timespec="milliseconds"), d, n, rssi, snr, info, hx])
            self.log[0].flush()

    def to_versal(self, s):
        with (self.writer or self.wlock):
            self.v.write((self.prefix + s + "\n").encode())

    @staticmethod
    def _readlines(port, name, handler, run):
        while run():
            try:
                raw = port.readline()
            except Exception as e:  # port unplugged
                print(f"{ts()}  {name} port error: {e}", flush=True)
                time.sleep(1)
                continue
            if raw:
                s = raw.decode(errors="replace").strip()
                if s:
                    handler(s)

    # ---------------- line handlers ----------------
    def on_versal(self, s):
        if s.startswith("TX,"):
            if len(s) < 5 or (len(s) - 3) % 2 or any(c not in "0123456789ABCDEFabcdef" for c in s[3:]):
                self.say(f"[versal] malformed TX line ignored ({len(s)} chars)")
                return
            self.txq.put(s[3:])
        elif s.startswith("ITX,"):
            # ITX,<peer SCID>,<hex>: a frame for the inter satellite link
            hx = s.split(",", 2)[2] if s.count(",") >= 2 else ""
            if len(hx) < 2 or len(hx) % 2 or any(c not in "0123456789ABCDEFabcdef" for c in hx):
                self.say(f"[versal] malformed ITX line ignored ({len(s)} chars)")
            elif self.isl is None:
                self.stats["isl_dropped"] = self.stats.get("isl_dropped", 0) + 1
                if self.stats["isl_dropped"] == 1:
                    self.say(f"SAT-{self.sat} sends ISL frames but no ISL radios were given (--isl{self.sat}-tx, --isl{self.sat}-rx)")
            else:
                self.isl.send(hx)
        elif s.startswith("LOG,"):
            self.stats["sat_logs"] += 1
            if s.startswith("LOG,PONG"):
                self.pong.set()
            self.say(f"SAT-{self.sat}  {s[4:]}")
            self.csv("sat", "", "", "", s[4:])      # satellite log lines kept with the frames
        else:
            self.say(f"[versal] {s}")        # boot messages from the PLM, Hello World etc.

    def on_rx_radio(self, s):
        if s.startswith("PKT,"):
            _, rssi, snr, hx = s.split(",", 3)
            r, q = int(float(rssi)), int(float(snr))
            self.stats["up"] += 1
            self.to_versal(f"R,{r},{q},{hx}")
            self.say(f"UP    {len(hx) // 2:3d} B  RSSI {r}  SNR {q}")
            self.csv("up", len(hx) // 2, r, q, "", hx)
        elif s == "CRCERR":
            self.stats["up_crc"] += 1
            self.to_versal("E")
            self.say("UP    CRC error")
        elif s.startswith("CFG,OK"):
            self.cfg_ok["rx"].set()
        elif s.startswith("MODEM"):
            self.say(f"RX radio: {s}")

    def on_radio(self, s):
        """Single-radio mode: one board both receives the uplink and sends the downlink."""
        if s.startswith("PKT,") or s == "CRCERR":
            self.on_rx_radio(s)
        elif s.startswith("SENT,"):
            self.sent.put(s)
        elif s.startswith("CFG,OK"):
            self.cfg_ok["tx"].set()
            self.cfg_ok["rx"].set()
        elif s.startswith("SF,OK"):
            self.say(f"SAT-{self.sat} radio: {s}")
        elif s.startswith("MODEM"):
            self.say(f"Satellite radio: {s}")

    def on_tx_radio(self, s):
        if s.startswith("SENT,"):
            self.sent.put(s)
        elif s.startswith("CFG,OK"):
            self.cfg_ok["tx"].set()
        elif s.startswith("MODEM"):
            self.say(f"TX radio: {s}")
        # PKT lines from the TX radio are ignored (it is not the receiver)

    # ---------------- workers ----------------
    def _tx_worker(self):
        while self._run:
            try:
                hx = self.txq.get(timeout=0.2)
            except queue.Empty:
                continue
            while not self.sent.empty():
                self.sent.get_nowait()
            n = len(hx) // 2
            vc = (int(hx[2:4], 16) >> 1) & 7 if n > 2 else -1
            write_paced(self.txr, f"TX,{hx}\n".encode())
            try:
                r = self.sent.get(timeout=4.0).split(",")
                ok = len(r) >= 3 and r[2] == "0"
                air = r[3] if len(r) > 3 else "?"
            except queue.Empty:
                ok, air = False, "timeout"
            if ok:
                self.stats["down"] += 1
                self.say(f"DOWN  {n:3d} B  VC{vc}  {air} ms")
            else:
                self.stats["down_fail"] += 1
                self.say(f"DOWN  {n:3d} B  VC{vc}  FAILED ({air})")
            self.csv("down", n, "", "", "ok" if ok else f"fail {air}", hx)

    def _heartbeat(self):
        while self._run:
            if self.cfg_ok["rx"].is_set():
                self.to_versal("H")
            time.sleep(2.0)

    def _configure(self, port, key, tx_mhz, rx_mhz, label):
        for _ in range(5):
            port.write(f"CFG,{tx_mhz:.3f},{rx_mhz:.3f}\n".encode())
            if self.cfg_ok[key].wait(1.5):
                self.say(f"{label} radio ready (tx {tx_mhz:.3f}  rx {rx_mhz:.3f} MHz)")
                if SAT_RADIO_SF:
                    time.sleep(0.2)
                    port.write(f"SF,{SAT_RADIO_SF}\n".encode())
                    self.say(f"{label} radio asked for spreading factor {SAT_RADIO_SF}; expect a line 'SF,OK,{SAT_RADIO_SF}'")
                return True
        self.say(f"WARNING {label} radio did not answer. Is it running modem.ino on the right COM port?")
        return False

    def start(self, read_versal=True):
        run = lambda: self._run  # noqa: E731
        ports = [(self.v, "Versal", self.on_versal)] if read_versal else []
        if self.single:
            ports.append((self.txr, "Satellite radio", self.on_radio))
        else:
            ports.append((self.rxr, "RX radio", self.on_rx_radio))
            ports.append((self.txr, "TX radio", self.on_tx_radio))
        for port, name, h in ports:
            threading.Thread(target=self._readlines, args=(port, name, h, run), daemon=True).start()

        if self.single:
            # one board: listen on the uplink, transmit on the downlink
            self._configure(self.txr, "tx", self.down_mhz, self.up_mhz, f"SAT-{self.sat}")
        else:
            self._configure(self.txr, "tx", self.down_mhz, self.down_mhz, "TX")
            self._configure(self.rxr, "rx", self.up_mhz, self.up_mhz, "RX")
        threading.Thread(target=self._tx_worker, daemon=True).start()
        threading.Thread(target=self._heartbeat, daemon=True).start()
        for _ in range(5):
            self.to_versal("P")
            if self.pong.wait(2.0):
                break
        else:
            self.say(f"WARNING no answer from SAT-{self.sat} on the Versal. Is its flight software running?")
        return self

    def stop(self):
        self._run = False
        if self.log:
            self.log[0].close()


class Demux:
    """Constellation mode: one UART, lines without prefix to the SAT-1 bridge,
    lines with "2:" to the SAT-2 bridge."""

    def __init__(self, versal, b1, b2):
        self.v, self.b1, self.b2 = versal, b1, b2
        self._run = True

    def start(self):
        threading.Thread(target=Bridge._readlines, args=(self.v, "Versal", self.on_line, lambda: self._run),
                         daemon=True).start()
        return self

    def on_line(self, s):
        if s.startswith("2:"):
            self.b2.on_versal(s[2:])
        else:
            self.b1.on_versal(s)



SAT_RADIO_SF = None        # set by --sf


def list_ports():
    from serial.tools import list_ports as lp
    for p in lp.comports():
        print(f"{p.device:8s} {p.description}  serial={p.serial_number}  vid:pid={p.vid}:{p.pid}")
    print("\nT-Beam S3 boards show as 'USB JTAG/serial debug unit' or 'USB Serial Device' (Espressif 303A:1001).")
    print("The Versal UART is the FTDI port that showed Hello World (COM7 on your laptop).")


def main():
    ap = argparse.ArgumentParser(description="Satellite 1 radio bridge (Versal <-> T-Beams)")
    ap.add_argument("--versal", help="Versal UART0 COM port, e.g. COM7")
    ap.add_argument("--tx", help="SAT-1 TX T-Beam COM port (two-radio satellite)")
    ap.add_argument("--rx", help="SAT-1 RX T-Beam COM port (two-radio satellite)")
    ap.add_argument("--radio", help="single satellite T-Beam COM port (half duplex, one USB port)")
    ap.add_argument("--radio2", help="SAT-2 T-Beam COM port: constellation mode, two satellites on the Versal")
    ap.add_argument("--isl1-tx", help="SAT-1 ISL transmit T-Beam (433.575 MHz)")
    ap.add_argument("--isl1-rx", help="SAT-1 ISL receive T-Beam (434.375 MHz)")
    ap.add_argument("--isl2-tx", help="SAT-2 ISL transmit T-Beam (434.375 MHz)")
    ap.add_argument("--isl2-rx", help="SAT-2 ISL receive T-Beam (433.575 MHz). Give the same COM as --isl2-tx to run "
                    "that satellite's side on one board in half duplex (three boards in all)")
    ap.add_argument("--isl-selftest", action="store_true", help="test the four ISL radios, no Versal needed")
    ap.add_argument("--sf", type=int, default=None, help="spreading factor of the satellite radios (868 MHz), e.g. 7. "
                    "Needs the modem firmware with the SF line. The ISL radios keep their setting")
    ap.add_argument("--log", default="sat1_bridge_log.csv")
    ap.add_argument("--list", action="store_true", help="list serial ports and exit")
    a = ap.parse_args()
    global SAT_RADIO_SF
    SAT_RADIO_SF = a.sf
    isl_ports = [a.isl1_tx, a.isl1_rx, a.isl2_tx, a.isl2_rx]
    if any(isl_ports) and not all(isl_ports):
        print("the RF inter satellite link needs all four: --isl1-tx --isl1-rx --isl2-tx --isl2-rx")
        return 2
    if a.isl_selftest:
        if not all(isl_ports):
            print("--isl-selftest needs --isl1-tx --isl1-rx --isl2-tx --isl2-rx")
            return 2
        import serial
        opened = {}
        for p in isl_ports:
            if p.upper() not in opened:
                opened[p.upper()] = serial.Serial(p, 115200, timeout=0.2)
        ip = [opened[p.upper()] for p in isl_ports]
        say = lambda s: print(f"{ts()}  {s}", flush=True)  # noqa: E731
        return isl_selftest(IslRadios(1, ip[0], ip[1], ISL_12_MHZ, ISL_21_MHZ, None, say),
                            IslRadios(2, ip[2], ip[3], ISL_21_MHZ, ISL_12_MHZ, None, say))
    single = bool(a.versal and a.radio)
    if a.list or not (single or (a.versal and a.tx and a.rx)):
        list_ports()
        if not a.list:
            print("\nusage: python sat_bridge.py --versal COM7 --radio COMx            (one satellite radio)")
            print("       python sat_bridge.py --versal COM7 --tx COMx --rx COMy    (two satellite radios)")
        return
    import serial
    if single and a.radio2:
        ports = [serial.Serial(p, 115200, timeout=0.2) for p in (a.versal, a.radio, a.radio2)]
        lock = threading.Lock()
        b = Bridge(ports[0], ports[1], ports[1], log_path=a.log, sat=1, writer=lock)
        b2 = Bridge(ports[0], ports[2], ports[2], log_path=a.log.replace(".csv", "_sat2.csv"), sat=2, writer=lock,
                    up_mhz=SAT2_UPLINK_MHZ, down_mhz=SAT2_DOWNLINK_MHZ)
        print(f"constellation bridge: Versal {a.versal}  SAT-1 radio {a.radio} ({UPLINK_MHZ}/{DOWNLINK_MHZ} MHz)  "
              f"SAT-2 radio {a.radio2} ({SAT2_UPLINK_MHZ}/{SAT2_DOWNLINK_MHZ} MHz)   (Ctrl+C to stop)")
        # Read the Versal first, so the satellite housekeeping reaches the ground straight away.
        # The inter satellite radios are set up after; until they are, the few ISL frames the
        # flight software emits are dropped harmlessly and the time sync retries.
        Demux(ports[0], b, b2).start()
        b.start(read_versal=False)
        b2.start(read_versal=False)
        print("Versal link up, satellite housekeeping flowing. Setting up the inter satellite radios ...")
        if all(isl_ports):
            def open_quiet(port):
                ser = serial.Serial()        # open without raising DTR and RTS, which reset a T-Beam
                ser.port = port
                ser.baudrate = 115200
                ser.timeout = 0.2
                ser.write_timeout = 2.0      # a board that enumerates but does not read must not hang the bridge
                try:
                    ser.dtr = False
                    ser.rts = False
                except Exception:
                    pass
                ser.open()
                return ser
            opened = {}                       # the same COM for a satellite's tx and rx = half duplex on one board
            for p in isl_ports:
                if p.upper() not in opened:
                    opened[p.upper()] = open_quiet(p)
            ip = [opened[p.upper()] for p in isl_ports]
            ports += list(opened.values())
            isl_log = a.log.replace(".csv", "_isl.csv")
            b.isl = IslRadios(1, ip[0], ip[1], ISL_12_MHZ, ISL_21_MHZ, b.to_versal, b.say, isl_log)
            b2.isl = IslRadios(2, ip[2], ip[3], ISL_21_MHZ, ISL_12_MHZ, b2.to_versal, b2.say, isl_log)
            b.isl.start()
            b2.isl.start()
            print(f"RF inter satellite link: SAT-1 to SAT-2 on {ISL_12_MHZ} MHz, SAT-2 to SAT-1 on {ISL_21_MHZ} MHz, "
                  f"full duplex, log {isl_log}")
        try:
            while True:
                for _ in range(30):
                    time.sleep(1)
                    # ISL restart experiment: frames recorded earlier are sent again on SAT-1's ISL
                    # transmitter when the file isl_replay.txt appears next to this script
                    if b.isl and os.path.exists("isl_replay.txt"):
                        with open("isl_replay.txt") as rf:
                            frames = [l.strip() for l in rf if l.strip()]
                        os.replace("isl_replay.txt", "isl_replay.done")
                        for hx in frames:
                            b.isl.send(hx)
                        print(f"{ts()}  --- ISL replay: {len(frames)} recorded frames queued on SAT-1's ISL transmitter", flush=True)
                for x in (b, b2):
                    s = x.stats
                    print(f"{ts()}  --- SAT-{x.sat} uplink {s['up']} (crc err {s['up_crc']})   downlink {s['down']} "
                          f"(failed {s['down_fail']})   queue {x.txq.qsize()}", flush=True)
                    if x.isl:
                        i = x.isl.stats
                        print(f"{ts()}  --- SAT-{x.sat} ISL sent {i['tx']} (failed {i['tx_fail']})   heard {i['rx']} "
                              f"(crc err {i['rx_crc']})   queue {x.isl.txq.qsize()}", flush=True)
        except KeyboardInterrupt:
            pass
        b.stop()
        b2.stop()
        for x in (b, b2):
            if x.isl:
                x.isl.stop()
        for p in ports:
            p.close()
        return
    if single:
        ports = [serial.Serial(p, 115200, timeout=0.2) for p in (a.versal, a.radio)]
        b = Bridge(ports[0], ports[1], ports[1], log_path=a.log)
        print(f"SAT-1 bridge: Versal {a.versal}  satellite radio {a.radio} (half duplex)   (Ctrl+C to stop)")
    else:
        ports = [serial.Serial(p, 115200, timeout=0.2) for p in (a.versal, a.tx, a.rx)]
        b = Bridge(*ports, log_path=a.log)
        print(f"SAT-1 bridge: Versal {a.versal}  TX radio {a.tx}  RX radio {a.rx}   (Ctrl+C to stop)")
    b.start()
    try:
        while True:
            time.sleep(30)
            s = b.stats
            print(f"{ts()}  --- uplink {s['up']} (crc err {s['up_crc']})   downlink {s['down']} "
                  f"(failed {s['down_fail']})   queue {b.txq.qsize()}", flush=True)
    except KeyboardInterrupt:
        pass
    b.stop()
    for p in ports:
        p.close()


if __name__ == "__main__":
    sys.exit(main())

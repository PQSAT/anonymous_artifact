"""
ccsds_link.py  -  Constellation testbed, Phase 3 ground station and user software.

Implements, to match the satellite firmware (ccsds_core.h):
  CCSDS 133.0  Space packets (TC without secondary header, TM with CUC secondary header)
  CCSDS 232.0  TC transfer frames (segment header, FECF)
  CCSDS 232.1  COP-1 sending side (FOP-1, stop-and-wait, Unlock / Set V(R) directives)
  CCSDS 132.0  TM transfer frames (OCF carrying the CLCW, FECF)
  CCSDS 301.0  CUC time code, 4 coarse + 2 fine octets, epoch 1970-01-01

Used by the ground notebook (laptop) and by user_terminal.py (Raspberry Pi).
Needs: pyserial.  Optional: pandas (for Terminal.dataframe()).
"""
import csv
import os
import datetime
import queue
import struct
import threading
import time

try:                      # SDLS by NASA CryptoLib, optional: without it the link runs in clear
    from sdls import (SdlsEndpoint, error_name as sdls_error_name, ROLE_USER, ROLE_GROUND, VC_TM_USER, VC_TM_GROUND,
                      SDLS_OVERHEAD)
    HAVE_SDLS = True
except Exception:         # noqa: BLE001
    HAVE_SDLS = False
    VC_TM_USER, VC_TM_GROUND, SDLS_OVERHEAD = 2, 4, 30

# ---------------- identifiers (ICD, same values as ccsds_core.h) ----------------
SCID_SAT1 = 0x101
SCID_SAT2 = 0x102
UPLINK_MHZ = 868.100            # SAT-1 channel pair (modem firmware defaults)
DOWNLINK_MHZ = 869.525
SAT2_UPLINK_MHZ = 868.300       # SAT-2 channel pair, see the constellation document
SAT2_DOWNLINK_MHZ = 868.500
TC_VC_GROUND, TC_VC_USER1 = 0, 1
TM_VC_HK, TM_VC_RELAY = 0, 1
APID_HK, APID_TC, APID_TC_ACK, APID_RELAY, APID_IDLE = 100, 500, 501, 600, 0x7FF
APID_AUTH = 700                 # three party authentication: src 2 | dst 2 | message
CMD_PING, CMD_SET_HK_RATE, CMD_SET_TIME, CMD_NAK, CMD_SA_STOP = 0x01, 0x02, 0x03, 0x0A, 0x0B
CMD_FORWARD, CMD_HANDOVER = 0x0C, 0x0D
CMD_NAMES = {CMD_PING: "PING", CMD_SET_HK_RATE: "SET_HK_RATE", CMD_SET_TIME: "SET_TIME", CMD_NAK: "NAK",
             CMD_SA_STOP: "SA_STOP", CMD_FORWARD: "FORWARD", CMD_HANDOVER: "HANDOVER"}

# Chunked downlink: a large APID 700 message arrives as one space packet per TM
# frame with sequence flags first (1), continuation (0), last (2); unsegmented
# is 3.  Each chunk carries dst (2), total (2), index (2) then up to 225 octets.
# TM frames have no retransmission, so the receiver asks for missing chunks by
# index with CMD_NAK, in the manner of CFDP class 2 deferred NAK.
CHUNK_HDR = 6
CHUNK_GAP_S = 6.0        # silence on an open message before asking for what is missing
CHUNK_NAK_MAX = 10       # rounds before the message is abandoned
CHUNK_NAK_LIST = 100     # chunk indices per NAK telecommand
STATUS = {0: "OK", 1: "BAD_ARG", 2: "UNKNOWN_CMD", 3: "NOT_ALLOWED"}
ADDR_GS, ADDR_USER1, ADDR_USER2 = 0x0001, 0x0011, 0x0012
ADDR_NAMES = {ADDR_GS: "GS", ADDR_USER1: "USER1", ADDR_USER2: "USER2"}
SEG_HDR_UNSEGMENTED = 0xC0      # sequence flags 11, MAP ID 0

# CCSDS 232.0 segment header sequence flags, and CCSDS 132.0 first header pointer.
SEG_CONT, SEG_FIRST, SEG_LAST, SEG_UNSEG = 0, 1, 2, 3
MAP_DEFAULT = 0
TC_SEG_MAX = 247                # 255 radio payload - 5 TC header - 1 segment header - 2 FECF
TM_DF_MAX = 243                 # 255 - 6 TM header - 4 OCF - 2 FECF
FHP_NONE = 0x7FF                # no packet starts in this frame
FHP_IDLE = 0x7FE                # frame carries only idle data


# ---------------- framing helpers ----------------
def crc16(data):
    c = 0xFFFF
    for byte in data:
        c ^= byte << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def space_packet(ptype, apid, seq, data, shdr=b""):
    n = len(shdr) + len(data) - 1
    hdr = bytes([(ptype << 4) | (0x08 if shdr else 0) | ((apid >> 8) & 7), apid & 0xFF,
                 0xC0 | ((seq >> 8) & 0x3F), seq & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    return hdr + bytes(shdr) + bytes(data)


def tc_frame(scid, vcid, ns, data, bypass=False, ctrl=False):
    n = 5 + len(data) + 2
    hdr = bytes([(int(bypass) << 5) | (int(ctrl) << 4) | ((scid >> 8) & 3), scid & 0xFF,
                 ((vcid & 0x3F) << 2) | (((n - 1) >> 8) & 3), (n - 1) & 0xFF, ns & 0xFF])
    body = hdr + bytes(data)
    c = crc16(body)
    return body + bytes([c >> 8, c & 0xFF])


def parse_clcw(c):
    return dict(type=c[0] >> 7, cop=c[0] & 3, vcid=c[1] >> 2, no_rf=(c[2] >> 7) & 1,
                lockout=(c[2] >> 5) & 1, wait=(c[2] >> 4) & 1, retransmit=(c[2] >> 3) & 1,
                farm_b=(c[2] >> 1) & 3, nr=c[3])


def parse_tm(b):
    """Return dict for a TM transfer frame, or raise ValueError."""
    if len(b) < 6 + 2:
        raise ValueError("short frame")
    if crc16(b[:-2]) != (b[-2] << 8 | b[-1]):
        raise ValueError("FECF/CRC mismatch")
    if b[0] >> 6 != 0:
        raise ValueError("not a TM v1 frame")
    ocf = b[1] & 1
    f = dict(scid=((b[0] & 0x3F) << 4) | (b[1] >> 4), vcid=(b[1] >> 1) & 7, mcfc=b[2], vcfc=b[3],
             fhp=((b[4] << 8) | b[5]) & 0x7FF)
    f["data"] = bytes(b[6:-6] if ocf else b[6:-2])
    f["clcw"] = parse_clcw(b[-6:-2]) if ocf else None
    return f


def parse_packet(p):
    if len(p) < 7:
        raise ValueError("short packet")
    L = ((p[4] << 8) | p[5]) + 1
    pk = dict(version=p[0] >> 5, type=(p[0] >> 4) & 1, shf=(p[0] >> 3) & 1,
              apid=((p[0] & 7) << 8) | p[1], seq=((p[2] & 0x3F) << 8) | p[3], flags=p[2] >> 6)
    body = bytes(p[6:6 + L])
    pk["time"] = None
    if pk["shf"] and pk["type"] == 0:
        sec, fine = struct.unpack(">IH", body[:6])
        pk["time"] = sec + fine / 65536.0
        body = body[6:]
    pk["data"] = body
    return pk


def parse_hk(d):
    v = struct.unpack(">HIHBB6HbbBB", d[:26])
    keys = ["scid", "uptime_s", "hk_period_s", "time_set", "rx_board_alive", "rx_frames", "crc_err",
            "id_err", "farm_discard", "cmds_ok", "relayed", "uplink_rssi", "uplink_snr", "vr_gs", "vr_user1"]
    return dict(zip(keys, v))


def lora_bitrate_bps(sf=9, bw=125e3, cr=3):
    """Physical layer bit rate of the LoRa channel: SF * BW / 2^SF * 4 / (4 + CR)."""
    return sf * bw / (2 ** sf) * 4.0 / (4 + cr)


def lora_airtime_ms(nbytes, sf=9, bw=125e3, cr=3, preamble=8):
    """LoRa time on air (explicit header, CRC on), cr=3 means 4/7."""
    ts = (2 ** sf) / bw * 1000
    de = 1 if ts > 16 else 0
    num = 8 * nbytes - 4 * sf + 28 + 16
    sym = 8 + max(-(-num // (4 * (sf - 2 * de))) * (cr + 4), 0)
    return (preamble + 4.25 + sym) * ts



# Radio setting of an experiment: PQSAT_SF=7 in the environment moves the air time model of
# the terminals and the modems (SF line, modem firmware of 17 November 2026) to that
# spreading factor.  Without it everything stays at SF9, the setting of the bench.
PQSAT_SF = int(os.environ.get("PQSAT_SF", "9"))
if PQSAT_SF != 9:
    lora_bitrate_bps.__defaults__ = (PQSAT_SF, 125e3, 3)
    lora_airtime_ms.__defaults__ = (PQSAT_SF, 125e3, 3, 8)


def write_paced(port, data, chunk=32, gap=0.005):
    """Write a long line to a T-Beam in small pieces.  The ESP32-S3 USB serial
    input buffer is 256 bytes and overflows silently, so a 255 octet frame
    (a 514 character line) written in one go arrives truncated or corrupted."""
    for i in range(0, len(data), chunk):
        port.write(data[i:i + chunk])
        port.flush()
        time.sleep(gap)


# ---------------- radio link (T-Beam running modem.ino) ----------------
class SerialLink:
    def __init__(self, port, baud=115200, tx_mhz=None, rx_mhz=None):
        """tx_mhz/rx_mhz retune the modem (CFG line) when given: a terminal served by
        SAT-2 uses SAT2_UPLINK_MHZ / SAT2_DOWNLINK_MHZ instead of the firmware defaults."""
        import serial
        self._serial, self._baud = serial, baud
        self._lock = threading.RLock()
        self._cfg_last = None                 # last frequency pair given, applied again after a reconnect
        self.reconnects = 0                   # times the USB port dropped and was opened again
        self.port = port
        self.ser = self._open()
        time.sleep(0.3)
        self.ser.reset_input_buffer()
        self.rx = queue.Queue()
        self.sent = queue.Queue()
        self.cfg = queue.Queue()
        self.crc_errors = 0
        self._run = True
        self._buf = b""
        self._t = threading.Thread(target=self._reader, daemon=True)
        self._t.start()
        self.freq_ok = None
        if tx_mhz is not None and rx_mhz is not None:
            self.freq_ok = self.retune(tx_mhz, rx_mhz)
        self.sf_ok = None
        if "PQSAT_SF" in os.environ:           # also PQSAT_SF=9, to bring a modem back to the bench setting
            self.sf_ok = self.set_sf(PQSAT_SF)
            print(f"radio {port}: spreading factor {PQSAT_SF}:", "OK" if self.sf_ok else
                  "NO ANSWER (the modem needs the firmware with the SF line)", flush=True)

    def set_sf(self, sf):
        """Set the modem's spreading factor (SF line).  Returns True when the modem acknowledges."""
        self._sf_last = sf
        for _ in range(4):
            self._sf_seen = False
            with self._lock:
                self.ser.write(f"SF,{sf}\n".encode())
                self.ser.flush()
            end = time.time() + 1.5
            while time.time() < end:
                if getattr(self, "_sf_seen", False):
                    return True
                time.sleep(0.05)
        return False

    def _open(self):
        """Open the port without resetting the board.  Opening a serial port normally raises
        DTR and RTS, and on the T-Beam those lines are the auto reset, so a plain open resets
        the ESP32.  We hold them low before opening so the board keeps running across a reopen."""
        ser = self._serial.Serial()
        ser.port = self.port
        ser.baudrate = self._baud
        ser.timeout = 0.1
        try:
            ser.dtr = False
            ser.rts = False
        except Exception:
            pass
        ser.open()
        return ser

    def retune(self, tx_mhz, rx_mhz):
        """Change the modem's transmit and receive frequencies (CFG line).  Used when a user
        is handed from one satellite to another and moves to the new satellite's channel pair.
        Returns True when the modem acknowledges."""
        self._cfg_last = (tx_mhz, rx_mhz)
        while not self.cfg.empty():
            try:
                self.cfg.get_nowait()
            except queue.Empty:
                break
        for _ in range(5):
            try:
                self.ser.write(f"CFG,{tx_mhz:.3f},{rx_mhz:.3f}\n".encode())
            except Exception:
                self._reopen()
                continue
            try:
                self.cfg.get(timeout=1.5)
                return True
            except queue.Empty:
                continue
        return False

    def _reopen(self, wait_s=90):
        """The USB port dropped (the board reset or the hub let go).  Close it, wait for the
        port to come back, open it again and give the modem its frequencies again.  The frame
        that was in flight is lost; COP-1 on the uplink and the repair on the downlink cover it."""
        with self._lock:
            if time.time() - getattr(self, "_reopened_at", 0) < 5.0:
                return True                    # the other thread has just opened it again
            try:
                self.ser.close()
            except Exception:
                pass
            end = time.time() + wait_s
            print(f"[link] {self.port} dropped off USB, waiting for it to come back ...", flush=True)
            while self._run and time.time() < end:
                try:
                    self.ser = self._open()
                    break
                except Exception:
                    time.sleep(1.0)
            else:
                print(f"[link] {self.port} did not come back in {wait_s} s", flush=True)
                return False
            time.sleep(2.5)                    # the modem firmware starts again after a reset
            try:
                self.ser.reset_input_buffer()
                if self._cfg_last is not None:
                    for _ in range(2):
                        self.ser.write(f"CFG,{self._cfg_last[0]:.3f},{self._cfg_last[1]:.3f}\n".encode())
                        time.sleep(0.4)
                if getattr(self, "_sf_last", None):     # a modem that restarted is back at SF9
                    for _ in range(2):
                        self.ser.write(f"SF,{self._sf_last}\n".encode())
                        time.sleep(0.4)
            except Exception:
                return False
            self._buf = b""
            self.reconnects += 1
            self._reopened_at = time.time()
            print(f"[link] {self.port} is back (reconnect {self.reconnects})", flush=True)
            return True

    def _reader(self):
        while self._run:
            try:
                chunk = self.ser.read(512)
            except Exception:
                if not self._run or not self._reopen():
                    break
                continue
            if not chunk:
                continue
            self._buf += chunk
            while b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                s = line.decode(errors="replace").strip()
                if s.startswith("PKT,"):
                    _, rssi, snr, hx = s.split(",", 3)
                    try:
                        self.rx.put((float(rssi), float(snr), bytes.fromhex(hx)))
                    except ValueError:
                        pass
                elif s.startswith("SENT,"):
                    self.sent.put(s)
                elif s == "CRCERR":
                    self.crc_errors += 1
                elif s.startswith("CFG,OK"):
                    self.cfg.put(s)
                elif s.startswith("SF,OK"):
                    self._sf_seen = True

    def send(self, frame):
        while not self.sent.empty():
            self.sent.get_nowait()
        try:
            with self._lock:
                write_paced(self.ser, ("TX," + frame.hex().upper() + "\n").encode())
        except Exception:
            self._reopen()
            return "SENT,reconnect"
        try:
            return self.sent.get(timeout=5)
        except queue.Empty:
            return "SENT,timeout"

    def recv(self, timeout):
        try:
            return self.rx.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self._run = False
        time.sleep(0.2)
        self.ser.close()


# ---------------- ground station / user terminal ----------------
class Terminal:
    """One CCSDS terminal: the ground station (TC VC0) or a user (TC VC1)."""

    def __init__(self, link, my_addr, tc_vc, scid=SCID_SAT1, name="GS", log_path=None,
                 show_hk=True, show_relay=True):
        self.link, self.my_addr, self.tc_vc, self.scid, self.name = link, my_addr, tc_vc, scid, name
        self.show_hk, self.show_relay = show_hk, show_relay
        self.cv = threading.Condition()
        self.clcw, self.clcw_n = None, 0          # latest CLCW for our TC VC
        self.acks = {}
        self.hk, self.inbox, self.rows = None, [], []
        self.samples = []            # metric samples: dict(t, kind, ...) see metrics()
        self.t_start = time.time()
        self.vs = 0                                # FOP V(S)
        self.pkt_seq = {APID_TC: 0, APID_RELAY: 0, APID_AUTH: 0}
        self.last_frame = None
        self.last_vcfc = {}
        self._tm_buf = {}           # per virtual channel partial packet, for spanned telemetry
        self.sdls = None            # SdlsEndpoint once a handshake has keyed the link
        self.sdls_role = ROLE_GROUND if (HAVE_SDLS and tc_vc == 0) else (ROLE_USER if HAVE_SDLS else None)
        self.sdls_tm_vc = VC_TM_GROUND if tc_vc == 0 else VC_TM_USER   # this terminal's protected downlink
        self.sdls_starts = 0
        self.auth_rx = []           # (src, message) authentication messages addressed to me
        self.chunks = {}                          # firstSeq -> open chunked message
        self.stats = dict(tm_frames=0, tm_bad=0, other_sc=0, tm_lost=0, tc_frames=0, tc_retx=0,
                          naks=0, chunks_repaired=0, chunks_abandoned=0,
                          sdls_tc_sent=0, sdls_tm_ok=0, sdls_tm_rejected=0, sdls_tm_unreadable=0,
                          lockouts=0)
        self.log_path = log_path
        if log_path:
            with open(log_path, "a", newline="") as fh:
                if fh.tell() == 0:
                    csv.writer(fh).writerow(["time", "dir", "rssi", "snr", "vc", "apid", "seq",
                                             "cuc", "info"])
        self._run = False

    # ---- background receive ----
    def start(self):
        self._run = True
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        return self

    def _loop(self):
        while self._run:
            ev = self.link.recv(0.2)
            if ev:
                try:
                    self._on_frame(*ev)
                except Exception as e:     # never let a bad frame kill the receiver
                    print(f"[{self.name}] receive error: {e}")

    def _log(self, d, rssi, snr, vc, apid, seq, cuc, info):
        row = dict(time=datetime.datetime.now().isoformat(timespec="milliseconds"), dir=d,
                   rssi=rssi, snr=snr, vc=vc, apid=apid, seq=seq, cuc=cuc, info=info)
        self.rows.append(row)
        if self.log_path:
            with open(self.log_path, "a", newline="") as fh:
                csv.writer(fh).writerow(row.values())

    def _on_frame(self, rssi, snr, b):
        try:
            f = parse_tm(b)
        except ValueError as e:
            self.stats["tm_bad"] += 1
            self._log("RX", rssi, snr, None, None, None, None, f"bad frame: {e}")
            return
        self.samples.append(dict(t=time.time(), kind="rx", bytes=len(b), vc=f["vcid"], rssi=rssi, snr=snr,
                                 air_ms=lora_airtime_ms(len(b))))
        if f["scid"] != self.scid:
            self.stats["other_sc"] += 1
            return
        self.stats["tm_frames"] += 1
        vc = f["vcid"]
        if vc in self.last_vcfc:
            gap = (f["vcfc"] - self.last_vcfc[vc] - 1) & 0xFF
            if 0 < gap < 128:
                self.stats["tm_lost"] += gap
        self.last_vcfc[vc] = f["vcfc"]

        c = f["clcw"]
        if c and c["vcid"] == self.tc_vc:
            with self.cv:
                self.clcw, self.clcw_n = c, self.clcw_n + 1
                if c["lockout"]:
                    self.stats["lockouts"] += 1
                self.cv.notify_all()

        data = f["data"]
        if vc in (VC_TM_USER, VC_TM_GROUND) and vc != self.sdls_tm_vc:
            return                                 # the other terminal's protected downlink, not ours to read
        if vc == self.sdls_tm_vc:                  # protected downlink: CryptoLib verifies and decrypts
            if self.sdls is None:
                self.stats["sdls_tm_unreadable"] += 1
                self._log("RX", rssi, snr, vc, None, None, None, "SDLS frame, no security association here")
                return
            data, r = self.sdls.tm_process(b)
            if data is None:
                self.stats["sdls_tm_rejected"] += 1
                self._log("RX", rssi, snr, vc, None, None, None, f"SDLS rejected: {sdls_error_name(r)}")
                print(f"[{self.name}] SDLS rejected a TM frame: {sdls_error_name(r)}")
                return
            self.stats["sdls_tm_ok"] += 1

        for raw in self._tm_reassemble(vc, f["fhp"], data):
            try:
                pk = parse_packet(raw)
            except ValueError as e:
                self.stats["tm_bad"] += 1
                self._log("RX", rssi, snr, vc, None, None, None, f"bad packet: {e}")
                continue
            self._on_packet(rssi, snr, vc, pk)

    def _tm_reassemble(self, vc, fhp, data):
        """Return the space packets this frame completes.

        The first header pointer says where the first packet of the frame
        starts, or FHP_NONE when the frame only continues a packet begun in an
        earlier frame.  That is how CCSDS 132.0 carries a packet larger than
        one transfer frame.
        """
        done, buf = [], self._tm_buf.get(vc)
        if fhp == FHP_IDLE:
            return done
        if fhp == FHP_NONE:
            if buf is None:
                return done                      # we missed the start of this packet
            buf = buf + data
        else:
            if buf is not None and fhp > 0:      # these octets finish the previous packet
                prev = buf + data[:fhp]
                if len(prev) >= 6 and len(prev) >= 6 + ((prev[4] << 8) | prev[5]) + 1:
                    done.append(prev)
            buf = data[fhp:]
        while buf is not None and len(buf) >= 6:
            total = 6 + ((buf[4] << 8) | buf[5]) + 1
            if len(buf) < total:
                break                            # still waiting for the rest
            done.append(buf[:total])
            buf = buf[total:] or None
        self._tm_buf[vc] = buf
        return done

    def _on_packet(self, rssi, snr, vc, pk):
        apid, d, info = pk["apid"], pk["data"], ""
        if apid == APID_HK:
            self.hk = parse_hk(d)
            self.hk["time"] = pk["time"]
            self.hk["rssi"], self.hk["snr"] = rssi, snr
            info = (f"HK up {self.hk['uptime_s']}s rx {self.hk['rx_frames']} ok {self.hk['cmds_ok']} "
                    f"relayed {self.hk['relayed']} discard {self.hk['farm_discard']} "
                    f"V(R) {self.hk['vr_gs']}/{self.hk['vr_user1']}")
            if self.show_hk:
                print(f"[{self.name}] {info}  RSSI {rssi:.0f}  SNR {snr:.1f}")
        elif apid == APID_TC_ACK:
            tc_seq, cmd, st = struct.unpack(">HBB", d[:4])
            with self.cv:
                self.acks[tc_seq] = st
                self.cv.notify_all()
            info = f"ACK tc_seq {tc_seq} {CMD_NAMES.get(cmd, hex(cmd))} {STATUS.get(st, st)}"
        elif apid == APID_RELAY:
            src, dst = struct.unpack(">HH", d[:4])
            text = d[4:].decode(errors="replace")
            info = f"MSG {ADDR_NAMES.get(src, hex(src))}->{ADDR_NAMES.get(dst, hex(dst))}: {text}"
            if dst == self.my_addr:
                self.inbox.append(dict(time=pk["time"], src=ADDR_NAMES.get(src, hex(src)), text=text))
                print(f"\n[{self.name}] message from {ADDR_NAMES.get(src, hex(src))}: {text}")
            elif self.show_relay:
                print(f"[{self.name}] relay seen {info}")
        elif apid == APID_AUTH and pk["flags"] != 3:
            info = self._on_chunk(pk)
        elif apid == APID_AUTH:
            info = self._deliver_auth(d)
        elif apid == APID_IDLE:
            info = "idle (COP-1 status)"
        self._log("RX", rssi, snr, vc, apid, pk["seq"], pk["time"], info)

    def _deliver_auth(self, d):
        src, dst = struct.unpack(">HH", d[:4])
        info = f"AUTH {ADDR_NAMES.get(src, hex(src))}->{ADDR_NAMES.get(dst, hex(dst))} type {d[4+1]:#04x} {len(d)-4} B"
        if dst == self.my_addr:
            self.auth_rx.append((src, bytes(d[4:])))
            with self.cv:
                self.cv.notify_all()
        return info

    def _on_chunk(self, pk):
        d = pk["data"]
        if len(d) < CHUNK_HDR:
            return "chunk too short"
        dst, total, idx = struct.unpack(">HHH", d[:CHUNK_HDR])
        if dst != self.my_addr or total == 0 or idx >= total:
            return f"chunk {idx}/{total} for {ADDR_NAMES.get(dst, hex(dst))}"
        first = (pk["seq"] - idx) & 0x3FFF
        m = self.chunks.get(first)
        if m is None:
            m = self.chunks[first] = dict(total=total, parts={}, t_last=time.time(), naks=0, repaired=0)
        m["t_last"] = time.time()           # any chunk, duplicate included, means the satellite is still serving us
        if idx in m["parts"]:
            return f"chunk {idx}/{total} duplicate"
        m["parts"][idx] = d[CHUNK_HDR:]
        if m["naks"]:
            m["repaired"] += 1
            self.stats["chunks_repaired"] += 1
        if len(m["parts"]) == total:
            del self.chunks[first]
            whole = b"".join(m["parts"][i] for i in range(total))
            return self._deliver_auth(whole) + f" ({total} chunks, {m['naks']} NAK rounds, {m['repaired']} repaired)"
        return f"chunk {idx}/{total} of message seq {first} ({len(m['parts'])} held)"

    def _repair_chunks(self):
        """Ask the satellite for the missing chunks of any message that has gone
        quiet.  Called from the waiting thread, never from the reader."""
        now = time.time()
        for first, m in list(self.chunks.items()):
            if now - m["t_last"] < CHUNK_GAP_S:
                continue
            missing = [i for i in range(m["total"]) if i not in m["parts"]]
            if m["naks"] >= CHUNK_NAK_MAX:
                print(f"[{self.name}] message seq {first} abandoned, {len(missing)} chunks never arrived")
                self.stats["chunks_abandoned"] += 1
                del self.chunks[first]
                continue
            m["naks"] += 1
            m["t_last"] = now
            self.stats["naks"] += 1
            ask = missing[:CHUNK_NAK_LIST]
            print(f"[{self.name}] NAK {m['naks']}: {len(missing)} of {m['total']} chunks missing, asking for {len(ask)}")
            body = bytes([CMD_NAK]) + struct.pack(">HB", first, len(ask)) + b"".join(struct.pack(">H", i) for i in ask)
            self.send_ad(space_packet(1, APID_TC, self._next_seq(APID_TC), body))

    # ---- COP-1 sending side (FOP-1) ----
    def _send_frame(self, frame, info):
        self.last_frame = frame
        self.stats["tc_frames"] += 1
        if self.sdls is not None and not (frame[0] & 0x10):      # data frames only; BC control frames stay clear
            prot, r = self.sdls.tc_apply(frame)
            if prot is None:
                print(f"[{self.name}] SDLS apply failed: {sdls_error_name(r)}")
                return "SDLS,ERR"
            frame = prot
            self.stats["sdls_tc_sent"] += 1
            info += " SDLS"
        res = self.link.send(frame)
        self._log("TX", None, None, self.tc_vc, None, None, None, f"{info} ({len(frame)} B) {res}")
        self.samples.append(dict(t=time.time(), kind="tx", bytes=len(frame), air_ms=lora_airtime_ms(len(frame))))
        return res

    def _wait_clcw(self, after_n, pred, timeout):
        end = time.time() + timeout
        with self.cv:
            while True:
                if self.clcw_n > after_n and pred(self.clcw):
                    return self.clcw
                left = end - time.time()
                if left <= 0:
                    return None
                self.cv.wait(left)

    def _directive(self, data, info, pred, tries=5, timeout=2.5):
        for _ in range(tries):
            n0 = self.clcw_n
            self._send_frame(tc_frame(self.scid, self.tc_vc, 0, data, bypass=True, ctrl=True), info)
            if self._wait_clcw(n0, pred, timeout):
                return True
        return False

    def init_cop(self):
        """FOP-1 'initiate AD service with Unlock and Set V(R)'."""
        ok = self._directive(b"\x00", "BC Unlock", lambda c: not c["lockout"])
        ok = ok and self._directive(bytes([0x82, 0x00, self.vs]), f"BC Set V(R)={self.vs}",
                                    lambda c: c["nr"] == self.vs)
        print(f"[{self.name}] COP-1 {'ready' if ok else 'NOT ready (no CLCW received)'}, V(S)={self.vs}")
        return ok

    def send_ad(self, packet, tries=6, timeout=2.5):
        """Send one space packet, sequence controlled (Type-AD).

        A packet larger than one frame is split into first, continuing and last
        segments as CCSDS 232.0 defines, each carried in its own frame.  COP-1
        acknowledges every segment, so a failure anywhere stops the transfer.
        """
        seg_max = TC_SEG_MAX - (SDLS_OVERHEAD if self.sdls is not None else 0)   # SDLS takes 30 octets per frame
        if len(packet) <= seg_max:
            return self._send_ad_segment(SEG_UNSEG, packet, tries, timeout)
        chunks = [packet[i:i + seg_max] for i in range(0, len(packet), seg_max)]
        last = len(chunks) - 1
        for i, c in enumerate(chunks):
            flag = SEG_FIRST if i == 0 else (SEG_LAST if i == last else SEG_CONT)
            if not self._send_ad_segment(flag, c, tries, timeout):
                return False
        return True

    def _send_ad_segment(self, flag, data, tries=6, timeout=2.5):
        target = (self.vs + 1) & 0xFF
        seg = bytes([((flag & 3) << 6) | (MAP_DEFAULT & 0x3F)])
        frame = tc_frame(self.scid, self.tc_vc, self.vs, seg + data)
        # FOP-1 T1 timer: the acknowledgement can only arrive after our own frame has
        # finished on air, the satellite has waited out its transmit pacing (up to one
        # full frame) and its frame carrying the CLCW (up to a full frame) has finished
        # on air.  Shorter than that, we retransmit while still deaf to the
        # acknowledgement and lose whatever the satellite sends meanwhile.
        timeout = max(timeout, (lora_airtime_ms(len(frame)) + 2 * lora_airtime_ms(255)) / 1000 + 0.4)
        for attempt in range(tries):
            if attempt:
                self.stats["tc_retx"] += 1
            n0 = self.clcw_n
            t_tx = time.time()
            self._send_frame(frame, f"AD N(S)={self.vs}" + (f" retry {attempt}" if attempt else ""))
            c = self._wait_clcw(n0, lambda c: c["nr"] == target or c["lockout"], timeout)
            if c and c["nr"] == target:
                self.vs = target
                # link RTT: segment on air to its COP-1 acknowledgement in a CLCW
                self.samples.append(dict(t=t_tx, kind="seg_rtt", ms=(time.time() - t_tx) * 1e3, bytes=len(frame),
                                         attempts=attempt + 1))
                return True
            if c and c["lockout"]:
                print(f"[{self.name}] FARM lockout reported, re-initialising COP-1")
                self.init_cop()
        return False

    # ---- services ----
    def _next_seq(self, apid):
        s = self.pkt_seq[apid]
        self.pkt_seq[apid] = (s + 1) & 0x3FFF
        return s

    def command(self, cmd, args=b"", wait_ack=3.0):
        seq = self._next_seq(APID_TC)
        t0 = time.time()
        self._cmd_t0 = t0
        if not self.send_ad(space_packet(1, APID_TC, seq, bytes([cmd]) + bytes(args))):
            print(f"[{self.name}] {CMD_NAMES.get(cmd, hex(cmd))}: not confirmed by COP-1")
            return None
        end = time.time() + wait_ack
        with self.cv:
            while seq not in self.acks and time.time() < end:
                self.cv.wait(end - time.time())
        st = self.acks.get(seq)
        # COP-1 confirmed delivery but the downlink frame carrying the ACK was lost:
        # the command did execute; verify it in the next HK if needed.
        name = STATUS.get(st, str(st)) if st is not None else "DELIVERED (ACK lost)"
        if st is not None:
            # application RTT: command sent to its acknowledgement packet received
            self.samples.append(dict(t=t0, kind="app_rtt", ms=(time.time() - t0) * 1e3, cmd=cmd))
        print(f"[{self.name}] {CMD_NAMES.get(cmd, hex(cmd))} tc_seq {seq}: {name}  "
              f"({(time.time() - t0) * 1000:.0f} ms)")
        return name

    def ping(self):
        return self.command(CMD_PING)

    def set_hk_rate(self, seconds):
        return self.command(CMD_SET_HK_RATE, struct.pack(">H", seconds))

    def forward_command(self, dst_scid, cmd, args=b"", wait_ack=20.0):
        """Command the neighbour satellite through this one (store and forward over the
        ISL).  The acknowledgement comes from the neighbour with this command's sequence
        count, so the wait covers one ISL round trip plus one downlink frame."""
        return self.command(CMD_FORWARD, struct.pack(">H", dst_scid) + bytes([cmd]) + bytes(args), wait_ack=wait_ack)

    def handover(self, serving_scid, user_addr, target_scid, user_key, wait_ack=90.0):
        """Hand over order: tell the user's serving satellite (through this satellite if it is
        not the serving one) to hand the user to the target satellite.  user_key is the key
        the user link runs under now (SK, or the next link key after an earlier hand over).
        The order carries a MAC under the order key derived from it, so only the ground
        station of this user's session can give it.  After the hand over the user link runs
        under pqsat_proto.next_link_key(user_key, target_scid)."""
        import pqsat_proto as P
        mac = P.order_mac(P.order_key(user_key), user_addr, serving_scid, target_scid)
        args = struct.pack(">HH", user_addr, target_scid) + mac
        if serving_scid == self.scid:
            return self.command(CMD_HANDOVER, args)
        # the serving satellite queues the key transfer (4456 octets, about 19 frames on the
        # inter satellite link) ahead of its acknowledgement, so the answer takes over 30 s
        return self.forward_command(serving_scid, CMD_HANDOVER, args, wait_ack=wait_ack)

    def sa_stop(self):
        """Ground only: stop the satellite's security associations (CCSDS 355.1 Stop SA)."""
        r = self.command(CMD_SA_STOP)
        self.sdls_stop()
        return r

    def set_time(self):
        return self.command(CMD_SET_TIME, struct.pack(">I", int(time.time())))

    def send_message(self, dst, text, limit=180):
        """Relay a message through the satellite.  Anything longer than one
        frame is segmented on the uplink and spanned on the downlink."""
        data = struct.pack(">HH", self.my_addr, dst) + text.encode()[:limit]
        ok = self.send_ad(space_packet(1, APID_RELAY, self._next_seq(APID_RELAY), data))
        print(f"[{self.name}] message to {ADDR_NAMES.get(dst, hex(dst))}: "
              f"{'accepted by satellite' if ok else 'NOT confirmed'}")
        return ok

    def send_auth(self, dst, msg):
        """Send one authentication message to `dst` through the satellite.  Large
        messages are segmented by send_ad.  Returns True when every segment was
        acknowledged."""
        data = struct.pack(">HH", self.my_addr, dst) + msg
        return self.send_ad(space_packet(1, APID_AUTH, self._next_seq(APID_AUTH), data))

    def sdls_start(self, sk):
        """Key this terminal's security associations from a completed handshake's
        session key.  The user protects its TC VC1, the ground its TC VC0, and both
        read the satellite's TM VC2.  A second call rekeys in place."""
        if not HAVE_SDLS:
            print(f"[{self.name}] SDLS library not available, link stays in clear")
            return False
        if self.sdls is None:
            self.sdls = SdlsEndpoint(self.scid, name=self.name.lower())
        self.sdls.start(sk, self.sdls_role)
        self.sdls_starts += 1
        self._tm_buf.pop(self.sdls_tm_vc, None)
        print(f"[{self.name}] SDLS {'rekeyed' if self.sdls_starts > 1 else 'started'}: "
              f"TC VC{self.tc_vc} protected on send, TM VC{self.sdls_tm_vc} verified on receive")
        return True

    def sdls_stop(self):
        if self.sdls is not None:
            self.sdls.stop()
            self.sdls = None

    def wait_auth(self, timeout):
        """Return the next (src, message) addressed to me, or None on timeout.
        Also drives chunk repair for messages in flight."""
        end = time.time() + timeout
        while True:
            with self.cv:
                if self.auth_rx:
                    return self.auth_rx.pop(0)
                left = end - time.time()
                if left <= 0:
                    return None
                self.cv.wait(min(left, 0.5))
            if self.chunks:
                self._repair_chunks()

    # ---- tests and reports ----
    def resend_last(self, timeout=2.5):
        """COP-1 check: retransmit the previous frame unchanged; FARM must discard it."""
        if not self.last_frame:
            print("nothing sent yet")
            return None
        n0 = self.clcw_n
        self._send_frame(self.last_frame, "copy of previous frame")
        c = self._wait_clcw(n0, lambda c: True, timeout)
        if c:
            print(f"[{self.name}] satellite CLCW after copy: N(R)={c['nr']} (unchanged = discarded), "
                  f"lockout={c['lockout']}")
        return c

    def duplex_test(self, n=10):
        """Send n PINGs back to back, ignoring satellite transmissions; report success and timing."""
        ok, times = 0, []
        for _ in range(n):
            t0 = time.time()
            if self.ping() == "OK":
                ok += 1
                times.append((time.time() - t0) * 1000)
        res = dict(sent=n, acked=ok, mean_ms=sum(times) / len(times) if times else None,
                   retransmissions=self.stats["tc_retx"])
        print(f"[{self.name}] duplex test: {res}")
        return res

    def status(self):
        print(f"[{self.name}] link stats: {self.stats}  V(S)={self.vs}  CLCW={self.clcw}")
        if self.hk:
            for k, v in self.hk.items():
                print(f"   {k:15s} {v}")
        return self.hk

    def wait(self, seconds):
        time.sleep(seconds)

    def metrics(self, since=None):
        """Network metrics from the samples collected since `since` (a time.time()
        value; default the terminal start), all from this terminal's point of view:
          throughput: octets received on the downlink per second and octets sent on the
                      uplink per second (frame octets, the goodput is computed per run
                      from the message sizes by the experiment)
          link_rtt:   telecommand segment to COP-1 acknowledgement, ms (min, mean, p50,
                      p95, max, count), the per segment round trip of the link
          app_rtt:    command to acknowledgement packet, ms
          bandwidth:  channel bit rate from the LoRa parameters and the utilisation
                      (fraction of wall time the terminal was sending or receiving)
        """
        t0 = self.t_start if since is None else since
        now = time.time()
        el = max(now - t0, 1e-6)
        ss = [x for x in self.samples if x["t"] >= t0]
        tx = [x for x in ss if x["kind"] == "tx"]
        rx = [x for x in ss if x["kind"] == "rx"]
        def stats(v):
            if not v:
                return dict(count=0)
            v = sorted(v)
            return dict(count=len(v), min=round(v[0], 1), mean=round(sum(v) / len(v), 1),
                        p50=round(v[len(v) // 2], 1), p95=round(v[min(len(v) - 1, int(len(v) * 0.95))], 1),
                        max=round(v[-1], 1))
        return dict(
            seconds=round(el, 3),
            throughput=dict(up_Bps=round(sum(x["bytes"] for x in tx) / el, 2),
                            down_Bps=round(sum(x["bytes"] for x in rx) / el, 2),
                            up_frames=len(tx), down_frames=len(rx)),
            link_rtt_ms=stats([x["ms"] for x in ss if x["kind"] == "seg_rtt"]),
            app_rtt_ms=stats([x["ms"] for x in ss if x["kind"] == "app_rtt"]),
            bandwidth=dict(channel_bps=round(lora_bitrate_bps(), 1),
                           utilisation_tx=round(sum(x["air_ms"] for x in tx) / 1e3 / el, 4),
                           utilisation_rx=round(sum(x["air_ms"] for x in rx) / 1e3 / el, 4)),
            rssi_dbm=stats([x["rssi"] for x in rx if x.get("rssi") is not None]),
            snr_db=stats([x["snr"] for x in rx if x.get("snr") is not None]),
        )

    def dataframe(self):
        import pandas as pd
        return pd.DataFrame(self.rows)

    def close(self):
        self._run = False
        time.sleep(0.3)
        self.link.close()
        print(f"[{self.name}] closed")

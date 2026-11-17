#!/usr/bin/env python3
"""Check of sat_bridge.py with the RF inter satellite link, on simulated modems (Linux, ptys).
Six simulated T-Beams speak the modem.ino line protocol; a simulated Versal speaks the
flight software's line protocol for two satellites behind sat_mux."""
import os, pty, select, subprocess, sys, threading, time, tty
HERE = os.path.dirname(os.path.abspath(__file__))
AIR = 0.05
air = {}


def mkpty():
    m, s = pty.openpty(); tty.setraw(m); tty.setraw(s); return m, os.ttyname(s)


class Modem(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True); self.m, self.port = mkpty(); self.tx = self.rx = 0.0; self.start()

    def run(self):
        buf = b""
        while True:
            buf += os.read(self.m, 4096)
            while b"\n" in buf:
                l, buf = buf.split(b"\n", 1); l = l.decode()
                if l.startswith("CFG,"):
                    _, t, r = l.split(","); self.tx, self.rx = float(t), float(r)
                    air.setdefault(self.rx, []).append(self)
                    os.write(self.m, f"CFG,OK,{t},{r}\n".encode())
                elif l.startswith("TX,"):
                    time.sleep(AIR)
                    for o in air.get(self.tx, []):
                        if o is not self:
                            os.write(o.m, f"PKT,-33.0,10.5,{l[3:]}\n".encode())
                    os.write(self.m, f"SENT,{len(l[3:]) // 2},0,{int(AIR * 1000)}\n".encode())


mods = [Modem() for _ in range(6)]          # sat1, sat2, isl1 tx, isl1 rx, isl2 tx, isl2 rx
vm, vport = mkpty()
got = []


def versal():
    buf = b""
    while True:
        buf += os.read(vm, 4096)
        while b"\n" in buf:
            l, buf = buf.split(b"\n", 1); l = l.decode()
            if l in ("P", "2:P"):
                os.write(vm, (l[:-1] + "LOG,PONG test\n").encode())
            elif l not in ("H", "2:H"):
                got.append(l)


threading.Thread(target=versal, daemon=True).start()
log = "/tmp/bridge_isl_test.csv"
for f in (log, log.replace(".csv", "_sat2.csv"), log.replace(".csv", "_isl.csv")):
    if os.path.exists(f): os.unlink(f)
p = subprocess.Popen([sys.executable, os.path.join(HERE, "sat_bridge.py"), "--versal", vport, "--radio", mods[0].port,
                      "--radio2", mods[1].port, "--isl1-tx", mods[2].port, "--isl1-rx", mods[3].port,
                      "--isl2-tx", mods[4].port, "--isl2-rx", mods[5].port, "--log", log], stdout=subprocess.DEVNULL)
time.sleep(4)
ok = tot = 0


def check(name, c):
    global ok, tot; tot += 1; ok += bool(c); print("PASS" if c else "FAIL", name)


check("ISL radios tuned: SAT-1 tx 433.575 rx 434.375, SAT-2 tx 434.375 rx 433.575",
      (mods[2].tx, mods[3].rx, mods[4].tx, mods[5].rx) == (433.575, 434.375, 434.375, 433.575))
f1 = [(bytes([0x10, 0x16, i]) + os.urandom(252)).hex().upper() for i in range(6)]
f2 = [(bytes([0x10, 0x26, i]) + os.urandom(252)).hex().upper() for i in range(6)]
dn = "101A" + "00" * 40
for a, b in zip(f1, f2):
    os.write(vm, f"ITX,102,{a}\n2:ITX,101,{b}\nTX,{dn}\n".encode())
time.sleep(3)
r2 = [l.split(",")[3] for l in got if l.startswith("2:I,")]
r1 = [l.split(",")[3] for l in got if l.startswith("I,")]
check("SAT-1 ISL frames reach SAT-2 as I lines, intact and in order", r2 == f1)
check("SAT-2 ISL frames reach SAT-1 as I lines, intact and in order", r1 == f2)
check("no ISL frame is delivered to a satellite as an uplink (R line)", not any(l.split(",")[-1] in f1 + f2 for l in got if "R," in l[:4]))
rows = open(log.replace(".csv", "_isl.csv")).read().count("\n") - 1
check("ISL log holds 24 rows (12 sent, 12 heard)", rows == 24)
check("the 868 MHz downlink still works beside the ISL", open(log).read().count(",down,") == 6)
print(f"{ok} of {tot}"); p.terminate(); sys.exit(0 if ok == tot else 1)

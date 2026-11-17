"""Hand /dev/ttyAMA0 over from the Linux login shell to the satellite.

Problem this solves: the login shell and the flight software both read the same
UART, so characters typed by hand are swallowed at random and the command never
arrives intact.  This sends each command repeatedly and checks the console until
it actually takes effect.

Run with the bridge stopped and PuTTY closed:
    python handover.py --versal COM7
"""
import argparse
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial is missing:  python -m pip install pyserial")

GETTY = "serial-getty@ttyAMA0.service"
HANDOVER = ("systemd-run --unit=go%d /bin/sh -c "
            "'systemctl stop " + GETTY + "; sleep 2; systemctl restart sat1.service'")


class Console:
    def __init__(self, port):
        self.p = serial.Serial(port, 115200, timeout=0.2)
        self.buf = ""

    def read(self):
        n = self.p.in_waiting
        if n:
            self.buf += self.p.read(n).decode("latin-1")
            self.buf = self.buf[-4000:]
        return self.buf

    def drain(self):
        self.read()
        self.buf = ""

    def send(self, line):
        self.p.write(("\n" + line + "\n").encode())
        self.p.flush()

    def close(self):
        self.p.close()


def quiet_for(c, seconds):
    """True if no satellite downlink line appears for this many seconds."""
    end = time.time() + seconds
    c.drain()
    while time.time() < end:
        time.sleep(0.2)
        if "TX," in c.read():
            return False
    return True


def shell_alive(c):
    c.drain()
    c.send("")
    time.sleep(1.0)
    return "root@" in c.read() or "#" in c.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--versal", required=True, help="serial port of the Versal console, e.g. COM7")
    ap.add_argument("--tries", type=int, default=25)
    a = ap.parse_args()

    c = Console(a.versal)
    print(f"console on {a.versal}")

    if not shell_alive(c):
        if "TX," in c.read():
            print("the satellite is transmitting but no shell prompt answered.")
            print("the shell may already be off the port.  try the bridge now.")
        else:
            print("nothing answered on this port.  check the cable and that Linux is booted.")
        c.close()
        return 1

    print("login shell is present, it has to go")

    # 1. silence the flight software so the console stops swallowing input
    if "TX," in c.read():
        print("stopping the flight software so commands can get through...")
        for i in range(a.tries):
            c.send("systemctl stop sat1.service")
            time.sleep(1.2)
            if quiet_for(c, 2.5):
                print(f"  quiet after {i + 1} attempt(s)")
                break
        else:
            print("could not silence it.  stop here and tell me.")
            c.close()
            return 1
    else:
        print("flight software already stopped")

    # 2. cancel the delayed console restore, it would break the link later
    for _ in range(3):
        c.send("systemctl stop console-restore.service")
        time.sleep(0.6)

    # 3. drop the shell off the port and bring the satellite back without it
    print("handing the port over to the satellite...")
    for i in range(6):
        c.send(HANDOVER % (i + 3))
        time.sleep(4.0)
        out = c.read()
        if "TX," in out:
            print("done.  the satellite is transmitting and the shell is gone.")
            print("now start the bridge:")
            print(r'  python sat_bridge.py --versal %s --radio COM6' % a.versal)
            c.close()
            return 0
        if "not found" in out or "Failed" in out:
            print("  attempt %d was mangled, retrying" % (i + 1))
    print("no downlink seen.  tell me what the console shows.")
    c.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())

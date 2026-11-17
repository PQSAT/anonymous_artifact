#!/usr/bin/env python3
"""Ground station terminal for Satellite 1, text version of ground_station.ipynb.

Run:   python3 gs_terminal.py                  (port auto: /dev/ttyACM0)
       python3 gs_terminal.py --port /dev/ttyACM1

Commands
  /ping            PING the satellite
  /time            set the satellite clock from this computer
  /rate <s>        set the housekeeping period, 2 to 60 seconds
  /hk on|off       show or hide each housekeeping packet
  /status          COP-1 state and counters
  /duplex <n>      send n commands back to back and report how many were acked
  /quit
Anything else you type is sent as a message to User 1 through the satellite.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from ccsds_link import SerialLink, Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--log", default="gs_log.csv")
    a = ap.parse_args()

    link = SerialLink(a.port)
    t = Terminal(link, ADDR_GS, TC_VC_GROUND, name="GS", log_path=a.log,
                 show_hk=True, show_relay=True).start()
    print(f"GS on {a.port}. Waiting for Satellite 1 ...")

    t.wait(25)
    if t.hk is None:
        print("no housekeeping yet. check the antenna and that the bridge is running.")
    else:
        print("housekeeping received, the satellite is in range")

    print("initialising COP-1 ...", "OK" if t.init_cop() else "FAILED")
    print("type /ping or a message, /quit to exit")

    try:
        while True:
            s = input("> ").strip()
            if not s:
                continue
            if s == "/quit":
                break
            elif s == "/ping":
                print(t.ping())
            elif s == "/time":
                print(t.set_time())
            elif s.startswith("/rate"):
                print(t.set_hk_rate(int(s.split()[1])))
            elif s == "/hk on":
                t.show_hk = True
            elif s == "/hk off":
                t.show_hk = False
            elif s == "/status":
                t.status()
            elif s.startswith("/duplex"):
                n = int(s.split()[1]) if len(s.split()) > 1 else 10
                print(t.duplex_test(n))
            else:
                t.send_message(ADDR_USER1, s)
    except (KeyboardInterrupt, EOFError):
        pass
    t.close()


if __name__ == "__main__":
    main()

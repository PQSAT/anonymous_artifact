#!/usr/bin/env python3
"""User terminal for Raspberry Pi (User 1). Talks to Satellite 1 through the USER T-Beam (modem.ino).

Run:   python3 user_terminal.py                 (port auto: /dev/ttyACM0)
       python3 user_terminal.py --port /dev/ttyACM1
Type a line and press Enter to send it to the ground station through Satellite 1.
Commands: /status   /hk on|off   /quit
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from ccsds_link import SerialLink, Terminal, ADDR_GS, ADDR_USER1, TC_VC_USER1  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM0")
    ap.add_argument("--log", default="user1_log.csv")
    a = ap.parse_args()

    link = SerialLink(a.port)
    t = Terminal(link, ADDR_USER1, TC_VC_USER1, name="USER1", log_path=a.log,
                 show_hk=False, show_relay=False).start()
    print(f"USER1 on {a.port}. Waiting for Satellite 1 ...")
    t.init_cop()
    print("Type a message and press Enter.  /status  /hk on  /hk off  /quit")
    try:
        while True:
            s = input("> ").strip()
            if not s:
                continue
            if s == "/quit":
                break
            if s == "/status":
                t.status()
            elif s == "/hk on":
                t.show_hk = True
            elif s == "/hk off":
                t.show_hk = False
            else:
                t.send_message(ADDR_GS, s)
    except (KeyboardInterrupt, EOFError):
        pass
    t.close()


if __name__ == "__main__":
    main()

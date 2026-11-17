"""Hand over on the bench: the user moves from SAT-2 to SAT-1 without a new handshake.

Constellation mode: the Versal runs SAT-1 (feeder, ground on its radio) and SAT-2 (serving,
user on its radio), joined by the inter satellite link, and the bridge runs with --radio2.

    python run_handover.py --gs COM4 --ue COM8                 one handshake then one hand over
    python run_handover.py --gs COM4 --ue COM8 --runs 5        repeat
    python run_handover.py --gs COM4 --ue COM8 --mode full     full certificates in the handshake

What happens in each run:
  1. the user authenticates with SAT-2, the ground with SAT-1, every message over the link
  2. the ground issues the hand over order for this user to SAT-2 (forwarded through SAT-1).
     The order carries a MAC under a key derived from this user's own session key, so only
     the ground station of this session can give it.  SAT-2 transfers a derived next link
     key to SAT-1 end to end (SAT-1 opens it, nothing in between can), then erases its copy
  3. the user retunes to SAT-1's channel pair and keys its link with the same derived key
  4. a protected message goes from the user to the ground over the new link

Measured: the hand over time (order sent to protected message delivered on the new link),
against the time a fresh handshake on the new satellite would have cost.  One JSON record
per run.  The campaign's stale link clearing runs before the first handshake.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
sys.path.insert(0, os.environ.get("PQSAT_DIR", os.path.join(HERE, "..", "protocol")))
from ccsds_link import (SerialLink, Terminal, ADDR_GS, ADDR_USER1, TC_VC_GROUND, TC_VC_USER1,  # noqa: E402
                        SCID_SAT1, SCID_SAT2, UPLINK_MHZ, DOWNLINK_MHZ, SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ)
from handshake_runner import run_handshake                                                   # noqa: E402
from pqsat_roles import HandshakeFailed                                                      # noqa: E402
import pqsat_proto as P                                                                      # noqa: E402
import auth_campaign                                                                         # noqa: E402


def wait_inbox(gs, text, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if any(text in m["text"] for m in gs.inbox):
            return True
        time.sleep(0.3)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gs", default="/dev/ttyACM0", help="ground station radio (SAT-1's channel pair)")
    ap.add_argument("--ue", default="/dev/ttyACM1", help="user radio (retuned to SAT-2's channel pair at start)")
    ap.add_argument("--mode", default="ref", choices=["full", "ref"])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or f"handover_hw_{a.mode}_{time.strftime('%Y%m%d_%H%M%S')}.json"

    gs = Terminal(SerialLink(a.gs), ADDR_GS, TC_VC_GROUND, scid=SCID_SAT1, name="GS", log_path="gs_handover_log.csv",
                  show_hk=False, show_relay=False).start()
    ue_link = SerialLink(a.ue, tx_mhz=SAT2_UPLINK_MHZ, rx_mhz=SAT2_DOWNLINK_MHZ)
    print(f"user radio on SAT-2's channels ({SAT2_UPLINK_MHZ} up / {SAT2_DOWNLINK_MHZ} down MHz):",
          "OK" if ue_link.freq_ok else "NO ANSWER (is modem.ino on this port?)")
    ue = Terminal(ue_link, ADDR_USER1, TC_VC_USER1, scid=SCID_SAT2, name="USER1", log_path="ue_handover_log.csv",
                  show_hk=False, show_relay=False).start()

    print("waiting for SAT-1 housekeeping at the ground ...")
    gs.wait(30)
    if gs.hk is None:
        print("no housekeeping. check the antenna, the bridge and that both satellites are running.")
        sys.exit(1)
    print("waiting for SAT-2 housekeeping at the user ...")
    ue.wait(30)
    if ue.hk is None:
        print("no SAT-2 housekeeping. check the second radio, --radio2 on the bridge and sat2.service.")
        sys.exit(1)
    if not auth_campaign.clear_link(gs):
        sys.exit(1)
    # SAT-2 may still protect the user link from an earlier completed handshake: the ground
    # tells it to stop, through SAT-1 over the inter satellite link
    from ccsds_link import CMD_SA_STOP, CMD_SET_TIME, CMD_PING
    import struct
    print("clearing link protection on SAT-2 (forwarded):", gs.forward_command(SCID_SAT2, CMD_SA_STOP, wait_ack=12.0))
    print("COP-1: ground", "OK" if gs.init_cop() else "FAILED", "user", "OK" if ue.init_cop() else "FAILED")
    print("setting SAT-1 clock:", gs.set_time())
    if not (ue.hk and ue.hk.get("time_set")):
        gs.forward_command(SCID_SAT2, CMD_SET_TIME, struct.pack(">I", int(time.time())), wait_ack=8.0)
        time.sleep(12)
    print("SAT-2 clock:", "set" if (ue.hk and ue.hk.get("time_set")) else "NOT confirmed")

    runs = []
    for i in range(a.runs):
        print(f"\n--- run {i + 1} of {a.runs}: handshake on SAT-2, hand over to SAT-1 ---")
        rec = dict(run=i + 1, started=time.strftime("%Y-%m-%d %H:%M:%S"), mode=a.mode)
        # the user is on SAT-2 for the handshake (after a previous run it has to come back)
        if i > 0:
            ue.sdls_stop()
            ue.link.retune(SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ)
            ue.scid = SCID_SAT2
            # whatever the last run left on SAT-2's user link is cleared, so the handshake starts in clear
            print("   clearing SAT-2's user link (forwarded):", gs.forward_command(SCID_SAT2, CMD_SA_STOP, wait_ack=12.0))
            ue.hk = None
            ue.wait(20)
            ue.init_cop()
        try:
            r = run_handshake(ue, gs, mode=a.mode, preload=True, sat="sat2", sat_id=SCID_SAT2)
        except HandshakeFailed as e:
            print("   handshake FAILED:", e)
            rec.update(handshake_ok=False, error=str(e))
            runs.append(rec)
            continue
        rec["handshake"] = dict(ok=r["ok"], seconds=r["seconds"], serving=f"{SCID_SAT2:#x}")
        if not r["ok"]:
            runs.append(rec)
            continue
        sk = bytes.fromhex(r["sk_user"])
        # keep the session key where the stale link clearing looks for it, so that a run that is
        # interrupted after this point does not leave the ground link locked
        with open(os.path.join(HERE, f"auth_hw_handover_keys_{time.strftime('%Y%m%d')}.json"), "w") as kf:
            json.dump([dict(ok=True, sk_ground=r.get("sk_ground") or r["sk_user"])], kf)
        print(f"   handshake on SAT-2: {r['seconds']} s")

        # The ground station has the session key as soon as MSG8 arrives, but SAT-1 keys the
        # ground link only when the whole key transfer from SAT-2 has crossed the inter satellite
        # link (4456 octets, about 40 s on the radio ISL).  A protected command sent before that
        # is not understood by SAT-1, so wait until a protected PING is answered.
        t_key = time.time()
        keyed = False
        for _ in range(30):
            if gs.command(CMD_PING) == "OK":
                keyed = True
                break
        rec["ground_link_keyed_after_s"] = round(time.time() - t_key, 1)
        print(f"   ground link protected on SAT-1 after {rec['ground_link_keyed_after_s']} s: {'yes' if keyed else 'NOT confirmed'}")

        # the hand over order: forwarded through SAT-1 to the serving satellite SAT-2
        t_ho = time.time()
        r_ho = gs.handover(SCID_SAT2, ADDR_USER1, SCID_SAT1, sk)
        t_order = time.time() - t_ho
        print(f"   hand over order to SAT-2 (through SAT-1): {r_ho} in {t_order:.1f} s")
        rec["order"] = dict(result=r_ho, seconds=round(t_order, 1))
        if r_ho != "OK" and not r_ho.startswith("DELIVERED"):
            print("   the order was refused. look in the bridge window for the reason.")
            runs.append(rec)
            continue
        if r_ho != "OK":
            print("   the order reached SAT-2 but its answer did not come back in time. the new link decides.")

        # the user moves to SAT-1 and keys its link with the derived next link key
        sk_next = P.next_link_key(sk, SCID_SAT1)
        ue.sdls_stop()
        ok_tune = ue.link.retune(UPLINK_MHZ, DOWNLINK_MHZ)
        ue.scid = SCID_SAT1
        ue.hk = None
        print(f"   user retuned to SAT-1's channels: {'OK' if ok_tune else 'NO ANSWER'}")
        ue.wait(15)
        heard = ue.hk is not None and ue.hk.get("scid") == SCID_SAT1
        print(f"   user hears SAT-1: {'yes' if heard else 'no'}")
        ue.init_cop()
        ue.sdls_start(sk_next)
        # SAT-1 keys the user link once the whole key transfer has crossed the inter satellite
        # link, so the first tries can be early: try again until the message arrives
        delivered = False
        for attempt in range(6):
            if ue.send_message(ADDR_GS, f"after hand over {i + 1}") and wait_inbox(gs, f"after hand over {i + 1}", 20):
                delivered = True
                break
            print(f"   not through yet (try {attempt + 1} of 6)")
            ue.init_cop()
        rec["handover_tries"] = attempt + 1
        t_total = time.time() - t_ho
        print(f"   protected message on the new link: {'delivered' if delivered else 'NOT delivered'}; "
              f"hand over {t_total:.1f} s against a fresh handshake of {r['seconds']} s")
        rec["handover"] = dict(seconds=round(t_total, 1), user_heard_sat1=heard, traffic_delivered=bool(delivered),
                               derived_key_used=True, handshake_would_cost_s=r["seconds"])
        runs.append(rec)
        with open(out, "w") as f:
            json.dump(runs, f, indent=1)

    good = [x for x in runs if x.get("handover", {}).get("traffic_delivered")]
    print(f"\n{len(good)} of {len(runs)} hand overs completed with protected traffic on the new link")
    if good:
        print(f"mean hand over {sum(x['handover']['seconds'] for x in good) / len(good):.1f} s, "
              f"mean handshake {sum(x['handshake']['seconds'] for x in good) / len(good):.1f} s")
    with open(out, "w") as f:
        json.dump(runs, f, indent=1)
    print("results ->", out)
    gs._run = ue._run = False


if __name__ == "__main__":
    main()

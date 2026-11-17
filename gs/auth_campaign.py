"""Post quantum handshake campaign over the real radio link (Linux laptop).

Ground station on one T-Beam, User 1 on the other, Satellite 1 on the Versal through
the bridge.  Runs the three party handshake N times and writes one JSON record per run
with per message octets, segments, retransmissions, frames, losses and wall clock, plus
the primitive timings on the user and ground.  The same run_handshake drives the
emulated link, so emulation and hardware numbers are directly comparable.

    python3 auth_campaign.py                       full certificates, 1 run
    python3 auth_campaign.py --mode ref --runs 20  reference mode, 20 runs
    python3 auth_campaign.py --gs /dev/ttyACM0 --ue /dev/ttyACM1
    python3 auth_campaign.py --constellation --mode ref   user served by SAT-2, ground by SAT-1
    python3 auth_campaign.py --mode ref --orbit high      conditions of the highest pass of PQSAT-8
    python3 auth_campaign.py --mode ref --orbit sweep --runs 6   six passes from high to low

Stale link protection: a completed handshake leaves the satellite protecting both links.  A
campaign that is started again has no key, so before the first run the tool checks that the
link answers in clear and, when it does not, sends the Stop SA command under the ground link
key of the last completed handshake (the same step as sa_recover.py).  --clear-between does
this after every run so that every handshake starts on a clear link.

Orbit conditions (--orbit): the pass window, the propagation delay and the frame loss from
the link margin of one pass of the PQSAT-8 model are applied between each terminal and its
radio (lib/orbit_link.py).  Each run is one pass.  The record carries the pass, what the
model removed and whether the handshake finished inside the window.

Constellation mode (--constellation): the Versal runs SAT-1 and SAT-2 (constellation_start.sh)
and the bridge runs with --radio2.  The user's T-Beam is retuned to SAT-2's channel pair,
the user authenticates with SAT-2 (0x102) and every message to the ground crosses the
inter satellite link to SAT-1.  The record carries which satellite served the user.

Before the first run the satellite must have been started with SAT_AUTH_DIR set (the
sat1_start.sh on the SD card does this) and, for reference mode, SAT_AUTH_REF=1 in the
unit.  Keys come from the protocol/keys directory produced by enrol.py; the satellite carries
sat1.bundle from the same enrolment.
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
                        SCID_SAT1, SCID_SAT2, SAT2_UPLINK_MHZ, SAT2_DOWNLINK_MHZ)
from handshake_runner import run_handshake                                                   # noqa: E402
from pqsat_roles import HandshakeFailed                                                      # noqa: E402
import pqsat_proto as P                                                                      # noqa: E402
import sa_recover                                                                            # noqa: E402
from ccsds_link import CMD_SA_STOP, CMD_SET_TIME                                             # noqa: E402
import struct                                                                               # noqa: E402


def clear_link(gs, key=None):
    """Make sure the ground link answers in clear.  key: ground link key of the last completed
    handshake; without one the newest result file in this folder is used."""
    gs.init_cop()
    if sa_recover.link_is_clear(gs):
        return True
    if key is None:
        found = sa_recover.last_session_key()
        if found is None:
            print("the link is protected and no result file holds a key: restart the satellite")
            return False
        print("stale link protection found. key taken from", os.path.basename(found[0]))
        key = found[1]
    return sa_recover.recover(gs, key)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gs", default="/dev/ttyACM0")
    ap.add_argument("--ue", default="/dev/ttyACM1")
    ap.add_argument("--mode", default="full", choices=["full", "ref"])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--out", default=None)
    ap.add_argument("--no-preload", action="store_true", help="do not pre cache certificates on user and ground")
    ap.add_argument("--constellation", action="store_true",
                    help="user on SAT-2 (fourth T-Beam, own channel pair), ground on SAT-1, ISL between them")
    ap.add_argument("--clear-between", action="store_true", help="stop link protection after every run")
    ap.add_argument("--orbit", default=None, help="apply one pass of the PQSAT-8 model: high, mid, low, a pass number or sweep")
    ap.add_argument("--pass-start", default="usable", help="where in the pass a run starts: usable (first second with "
                    "modelled loss under 10 percent), rise, or seconds after rise")
    ap.add_argument("--seed", type=int, default=1, help="seed of the modelled frame loss")
    ap.add_argument("--orbit-ground", action="store_true",
                    help="also put a pass model on the ground link (default: the pass is applied to the user link only; "
                         "the feeder link is the bench link as it is)")
    a = ap.parse_args()
    tag = ("const_" if a.constellation else "") + ("orbit_" if a.orbit else "")
    out = a.out or f"auth_hw_{tag}{a.mode}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    sat, sat_id = ("sat2", SCID_SAT2) if a.constellation else ("sat1", SCID_SAT1)

    gs_link = SerialLink(a.gs)
    models = []
    if a.orbit:
        from orbit_link import PassModel, ModelledLink
        first = "high" if a.orbit == "sweep" else a.orbit
        models = [PassModel(site="ground", choose=first, seed=a.seed), PassModel(site="user", choose=first, seed=a.seed + 1)]
        if a.orbit_ground:
            gs_link = ModelledLink(gs_link, models[0])
    gs = Terminal(gs_link, ADDR_GS, TC_VC_GROUND, name="GS", log_path="gs_auth_log.csv",
                  show_hk=False, show_relay=False).start()
    if a.constellation:
        ue_link = SerialLink(a.ue, tx_mhz=SAT2_UPLINK_MHZ, rx_mhz=SAT2_DOWNLINK_MHZ)
        print(f"user radio retuned to SAT-2's channels ({SAT2_UPLINK_MHZ} up / {SAT2_DOWNLINK_MHZ} down MHz):",
              "OK" if ue_link.freq_ok else "NO ANSWER (is modem.ino on this port?)")
    else:
        ue_link = SerialLink(a.ue)
    if a.orbit:
        ue_link = ModelledLink(ue_link, models[1])
    ue = Terminal(ue_link, ADDR_USER1, TC_VC_USER1, scid=sat_id, name="USER1", log_path="ue_auth_log.csv",
                  show_hk=False, show_relay=False).start()

    print("waiting for SAT-1 housekeeping at the ground ...")
    gs.wait(30)
    if gs.hk is None:
        print("no housekeeping. check the antenna, the bridge and that sat1.service is running.")
        sys.exit(1)
    if a.constellation:
        print("waiting for SAT-2 housekeeping at the user ...")
        ue.wait(30)
        if ue.hk is None:
            print("no SAT-2 housekeeping. check the fourth T-Beam, --radio2 on the bridge and sat2.service.")
            sys.exit(1)
        print(f"user hears SCID {ue.hk.get('scid'):#x}")
    if not clear_link(gs):
        sys.exit(1)
    print("satellites in range. initialising COP-1: ground", "OK" if gs.init_cop() else "FAILED",
          "user", "OK" if ue.init_cop() else "FAILED")
    print("setting SAT-1 clock from the ground:", gs.set_time())
    if a.constellation:
        # SAT-2 may still protect the user link from an earlier completed handshake
        print("clearing link protection on SAT-2 (forwarded):", gs.forward_command(SCID_SAT2, CMD_SA_STOP, wait_ack=12.0))
        ue.init_cop()
        # SAT-2 serves the user, so SAT-2 checks MSG1's timestamp. It needs a real clock. The
        # ground forwards SET_TIME to SAT-2 through SAT-1 over the ISL, and we confirm from the
        # user's own view of SAT-2 (its housekeeping carries time_set), retrying, because the
        # forward's acknowledgement is often lost on the downlink even when the command arrived.
        set_ok = bool(ue.hk and ue.hk.get("time_set"))
        for attempt in range(6):
            if set_ok:
                break
            gs.forward_command(SCID_SAT2, CMD_SET_TIME, struct.pack(">I", int(time.time())), wait_ack=6.0)
            end = time.time() + 14
            while time.time() < end:
                if ue.hk and ue.hk.get("time_set"):
                    set_ok = True
                    break
                time.sleep(1)
            print(f"   SAT-2 clock attempt {attempt + 1}: {'set' if set_ok else 'not yet, retrying'}")
        print("setting SAT-2 clock over the ISL:", "OK (SAT-2 reports its clock is set)" if set_ok
              else "NOT confirmed. The SAT-1 to SAT-2 ISL direction may be dropping frames; the handshake may fail.")

    runs = []
    last_key = None
    for i in range(a.runs):
        print(f"\n--- handshake {i + 1} of {a.runs}, mode {a.mode} ---")
        info = None
        if a.orbit:
            if a.orbit == "sweep":                      # passes spread from the highest to the lowest
                ranked = sorted(models[1].all_passes, key=lambda p: -p["max_elevation"])
                pick = ranked[min(len(ranked) - 1, i * max(1, len(ranked) // max(1, a.runs)))]
                idx = models[1].all_passes.index(pick)
                models = [PassModel(site="ground", choose=idx, seed=a.seed + 2 * i), PassModel(site="user", choose=idx, seed=a.seed + 2 * i + 1)]
                ue.link.model = models[1]
                if a.orbit_ground:
                    gs.link.model = models[0]
            info = models[1].describe()
            off = 0.0 if a.pass_start == "rise" else (info["usable_from_s"] or 0.0) if a.pass_start == "usable" else float(a.pass_start)
            print(f"   pass of {info['satellite']}, maximum elevation {info['max_elevation_deg']} deg, {info['pass_seconds']:.0f} s, "
                  f"margin {info['margin_db_at_rise']} dB at rise and {info['margin_db_at_peak']} dB at the peak ({info['profile']}), "
                  f"usable {info['usable_seconds']:.0f} s, run starts {off:.0f} s after rise")
            for m in (models if a.orbit_ground else models[1:]):
                m.start(off)
        try:
            r = run_handshake(ue, gs, mode=a.mode, preload=not a.no_preload, sat=sat, sat_id=sat_id)
            r["serving_satellite"] = f"{sat_id:#x}"
            last_key = bytes.fromhex(r["sk_ground"]) if r.get("sk_ground") else last_key
        except HandshakeFailed as e:
            r = dict(mode=a.mode, ok=False, error=str(e), seconds=None)
            print("   FAILED:", e)
        if a.orbit:
            end = models[1].tau()
            r["orbit"] = dict(info, start_offset_s=off, end_offset_s=round(end, 1), inside_pass=end <= info["pass_seconds"],
                              user_link=dict(models[1].stats), ground_link=dict(models[0].stats),
                              ground_link_modelled=bool(a.orbit_ground), trace=models[1].trace)
            print(f"   model: user link removed {models[1].stats['sent_removed']} of {models[1].stats['sent']} sent and "
                  f"{models[1].stats['received_removed']} of {models[1].stats['received']} received; "
                  f"ground link {models[0].stats['sent_removed']} of {models[0].stats['sent']} and "
                  f"{models[0].stats['received_removed']} of {models[0].stats['received']}; run ended {end:.0f} s after rise")
            for m in models:
                m.stop()
        if (a.clear_between or a.orbit) and i + 1 < a.runs:
            if ue.sdls is not None:                     # the user stops the associations of its serving satellite
                ue.command(CMD_SA_STOP, wait_ack=2.0)
            ue.sdls_stop()
            time.sleep(1.0)
            if not clear_link(gs, last_key if r.get("ok") else None):
                print("   the link could not be cleared: stopping the campaign")
                r["run"] = i + 1
                runs.append(r)
                break
            gs.init_cop(); ue.init_cop()
        r["run"] = i + 1
        r["started"] = time.strftime("%Y-%m-%d %H:%M:%S")
        runs.append(r)
        with open(out, "w") as f:
            json.dump(runs, f, indent=1)

    good = [r for r in runs if r.get("ok")]
    print(f"\n{len(good)} of {len(runs)} handshakes completed")
    if good:
        print(f"mean {sum(r['seconds'] for r in good)/len(good):.1f} s, "
              f"{sum(r['uplink_segments'] for r in good)/len(good):.0f} uplink segments "
              f"({sum(r['uplink_retransmissions'] for r in good)/len(good):.1f} retx), "
              f"{sum(r['downlink_frames'] for r in good)/len(good):.0f} downlink frames "
              f"({sum(r['downlink_lost'] for r in good)/len(good):.1f} lost)")
    print("results ->", out)
    gs._run = ue._run = False


if __name__ == "__main__":
    main()

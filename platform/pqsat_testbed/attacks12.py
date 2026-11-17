"""The twelve attack classes of the S&P plan (workstream B), as a catalogue the dashboard
shows and a harness the platform runs.

Each class says where the adversary acts (message, frame, behaviour or node), what the
unprotected baseline is expected to do (the attack succeeds), what the protected system is
expected to do (which layer rejects it) and what evidence is recorded.  The harness runs a
class on a backend through the platform's existing attack plug ins when they exist
(plugins/attacks.py: replay_msg1, forged_msg3, junk_msg1, stale_msg1, sdls_clear,
sdls_replay, sdls_flip) and through the adversary node for the classes that need frames on
the air (a fifth T-Beam driven by the bridge with --adversary, or the emulator's adversary
modem).  Classes 8 to 12 are implemented here on top of the terminal library; they are
marked `needs` with what they require so a run without it reports "not run" rather than a
false pass.

Evidence: every run writes the frames it sent and the satellite's and terminals' reactions
into the platform database (table attacks: run_id, class, variant, baseline_or_protected,
outcome, rejected_by, capture_id) and a capture file cap_<id>.jsonl beside the database.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional


@dataclass
class AttackClass:
    key: str
    name: str
    layer: str                       # message | frame | behaviour | node
    description: str
    baseline: str                    # expected outcome against the unprotected system
    protected: str                   # expected outcome against the protected system
    rejected_by: str
    needs: List[str] = field(default_factory=list)     # e.g. ["adversary_radio"], ["revocation_list"]
    plugin: Optional[str] = None     # name in plugins/attacks.py when one exists
    suite: Optional[str] = None      # section of protocol/test_attacks_protocol.py that exercises the class at the protocol layer
    emu_test: Optional[str] = None   # a test under flight/apps/sat_rf/test that exercises the class over the emulated link


CATALOGUE: List[AttackClass] = [
    AttackClass("replay_handshake", "Replay of a complete handshake and of single messages", "message",
                "A captured MSG1 (and later each of MSG3, MSG5, MSG7) is sent again inside and outside the freshness window.",
                "accepted; a second session is opened with stale material", "rejected", "satellite replay cache (inside the window), freshness window (outside)", plugin="replay_msg1", suite="B5"),
    AttackClass("forged_message", "Forged messages with valid framing", "message",
                "A syntactically valid MSG1 or MSG3 with a changed nonce or one flipped bit in the signature.",
                "accepted", "rejected", "user signature (ML-DSA half) or ground signature; junk MSG1 never reaches the ground", plugin="forged_msg3"),
    AttackClass("bit_flip", "Modification of a message in flight, bit by bit", "frame",
                "Every protected frame of a handshake is sent with one bit flipped in the data field.",
                "accepted; the message is corrupted and the handshake fails or a wrong key results", "rejected", "SDLS MAC on protected frames; hybrid signature on clear handshake messages", plugin="sdls_flip"),
    AttackClass("mitm_relay", "Man in the middle through the satellite's relay role", "node",
                "An adversary satellite instance relays between the user and the real satellite, forwarding MSG1 and substituting its own KEM ciphertext.",
                "accepted; the adversary holds a shared secret with one side", "rejected", "transcript binding of the ciphertext hash and the hybrid signature; the user's tag over ss_us and ss_gu fails", suite="B1"),
    AttackClass("downgrade", "Downgrade between classical and post quantum modes", "message",
                "During migration the adversary rewrites the mode field of MSG1 to classical and answers with a classical MSG4.",
                "accepted; classical keys are negotiated", "rejected", "mode is bound in the transcript signed by all three parties", suite="B2"),
    AttackClass("reassembly_hold", "Denial of service through incomplete segmented telecommands", "behaviour",
                "The adversary sends the first segments of many large telecommands and never the last, holding reassembly state on the satellite.",
                "state held until reboot; live uplink blocked", "finding: the inactivity timer (30 s) frees the state; one buffer per virtual channel; the genuine user's next telecommand replaces it; no state at all on the protected link", "reassembly timer and per VC buffer bound; SDLS on the protected link", needs=["adversary_radio"], emu_test="test_reassembly_hold.py"),
    AttackClass("window_vs_segments", "Denial through the anti replay window against segment ordering", "frame",
                "Frames are replayed and reordered so that the ARSN window advances past live segments.",
                "live segments rejected", "rejected replays, live traffic unaffected", "SDLS after COP-1: in order delivery, fresh ARSN per retransmission", plugin="sdls_replay"),
    AttackClass("airtime_exhaustion", "Air time exhaustion by junk MSG1", "behaviour",
                "Continuous junk MSG1 at the user channel occupy the half duplex link.",
                "link busy 100 %", "finding: the signature rejects every message but the air time is spent; busy fraction reported", "nothing below the signature: the link layer has no admission control", needs=["adversary_radio"], plugin="junk_msg1"),
    AttackClass("replayed_handover", "Replay of a handover (USERSESS over the ISL)", "message",
                "A captured USERSESS packet is replayed on the ISL to key a satellite with an old session.",
                "accepted; an old session key is installed", "rejected", "SDLS anti replay on the ISL association; session binding to the user's identity", needs=["isl_capture"], emu_test="test_isl_key_compromise.py"),
    AttackClass("revocation_suppression", "Suppression of the revocation list and use of a revoked identity", "behaviour",
                "The adversary blocks CRL distribution and authenticates with a revoked certificate.",
                "accepted", "rejected once the CRL has reached the satellite; finding: window between revocation and distribution measured", "revocation list checked at MSG1 and MSG3", suite="B4"),
    AttackClass("compromised_isl_key", "Compromise of one pairwise ISL key", "node",
                "The adversary holds K_ISL of one pair and injects frames on that ISL.",
                "n/a", "contained: only that pair is affected; forwarded commands and hand overs on other pairs unaffected; rekey by the registry", "pairwise keys and the ground's FORWARD authority", needs=["isl_capture"], emu_test="test_isl_key_compromise.py"),
    AttackClass("session_state_corruption", "Session state corruption (Canetti Krawczyk)", "message",
                "The adversary obtains a party's ephemeral state (nonces, one shared secret) after the handshake.",
                "n/a", "session key stays secret while two of the three shared secrets are unknown; proved in ProVerif, tested by unwrapping with one secret", "key derivation over three KEM secrets and three nonces", suite="B3"),
]


def catalogue() -> List[dict]:
    return [asdict(c) for c in CATALOGUE]


class AttackRun:
    """Run one class against a backend.  `platform` is the platform object (or None),
    `nodes` the backend's nodes.  When the platform's attack plug in exists it is used;
    otherwise the class's `needs` decide whether it runs here or is reported as not run."""

    def __init__(self, db_path: str, run_id: str, log: Callable[[str], None] = print):
        self.db_path, self.run_id, self.log = db_path, run_id, log
        self.cap_dir = os.path.join(os.path.dirname(os.path.abspath(db_path)), "captures")
        os.makedirs(self.cap_dir, exist_ok=True)
        self.results: List[dict] = []

    def _capture(self, cls: str, variant: str, frames: List[dict]) -> str:
        cid = f"{self.run_id}_{cls}_{variant}"
        with open(os.path.join(self.cap_dir, f"cap_{cid}.jsonl"), "w") as f:
            for fr in frames:
                f.write(json.dumps(fr) + "\n")
        return cid

    def record(self, cls: str, variant: str, outcome: str, rejected_by: str, frames: Optional[List[dict]] = None, note: str = ""):
        cid = self._capture(cls, variant, frames or [])
        row = dict(run_id=self.run_id, cls=cls, variant=variant, outcome=outcome, rejected_by=rejected_by, capture=cid, note=note, t=time.time())
        self.results.append(row)
        try:
            import sqlite3
            db = sqlite3.connect(self.db_path)
            db.execute("CREATE TABLE IF NOT EXISTS attacks(run_id TEXT, cls TEXT, variant TEXT, outcome TEXT, rejected_by TEXT, capture TEXT, note TEXT, t REAL)")
            db.execute("INSERT INTO attacks VALUES(?,?,?,?,?,?,?,?)", tuple(row.values()))
            db.commit(); db.close()
        except Exception as e:
            self.log(f"attack record not stored: {e}")
        self.log(f"attack {cls} [{variant}]: {outcome} ({rejected_by})")
        return row

    def run_all(self, platform=None, nodes=None, available: Optional[Dict[str, bool]] = None) -> List[dict]:
        available = available or {}
        for c in CATALOGUE:
            missing = [n for n in c.needs if not available.get(n)]
            if c.plugin and platform is not None and hasattr(platform, "attack_plugins") and c.plugin in platform.attack_plugins:
                for variant in ("baseline", "protected"):
                    try:
                        r = platform.attack_plugins[c.plugin].run(nodes, protected=(variant == "protected"))
                        self.record(c.key, variant, r.get("outcome", "?"), r.get("rejected_by", c.rejected_by if variant == "protected" else "none"), r.get("frames"))
                    except Exception as e:
                        self.record(c.key, variant, "error", str(e))
            elif missing:
                self.record(c.key, "protected", "not run", f"needs {', '.join(missing)}")
            else:
                self.record(c.key, "protected", "not run", "no harness for this class on this backend")
        return self.results


def run_protocol_suite(pqc_dir: str, runner: Optional["AttackRun"] = None, python: Optional[str] = None) -> List[dict]:
    """Run protocol/test_attacks_protocol.py (Python roles and the flight C satellite, no link) and
    record one result per class from its sections: B1 man in the middle, B2 downgrade,
    B3 session state and forward secrecy, B4 revocation, B5 replay of later messages."""
    import subprocess
    import sys
    out = subprocess.run([python or sys.executable, "test_attacks_protocol.py"], cwd=pqc_dir, capture_output=True,
                         text=True, timeout=1800).stdout
    rows = []
    for c in CATALOGUE:
        if not c.suite:
            continue
        lines = [l for l in out.splitlines() if l[5:].startswith(c.suite + " ") or l[5:].startswith("C  " + c.suite + " ")]
        passed = [l for l in lines if l.startswith("PASS")]
        outcome = "not run" if not lines else ("rejected" if len(passed) == len(lines) else "FAILED")
        row = dict(cls=c.key, variant="protected", outcome=outcome, rejected_by=c.rejected_by,
                   note=f"{len(passed)} of {len(lines)} protocol layer checks", checks=lines)
        rows.append(row)
        if runner is not None:
            runner.record(c.key, "protected", outcome, c.rejected_by, [dict(check=l) for l in lines], row["note"])
    return rows


def run_emu_suite(test_dir: str, runner: Optional["AttackRun"] = None, python: Optional[str] = None) -> List[dict]:
    """Run the emulator attack tests under flight/apps/sat_rf/test (the flight core over the
    simulated link) and record one result per class whose emu_test names such a test:
    reassembly_hold, replayed_handover and compromised_isl_key.  Each test ends with a
    'N/N checks passed' line."""
    import subprocess
    import sys
    rows = []
    seen = {}
    for c in CATALOGUE:
        if not c.emu_test or c.emu_test in seen:
            if c.emu_test:
                rows.append(dict(seen[c.emu_test], cls=c.key))
            continue
        try:
            out = subprocess.run([python or sys.executable, c.emu_test], cwd=test_dir, capture_output=True,
                                 text=True, timeout=3600).stdout
        except Exception as e:                       # noqa: BLE001
            row = dict(cls=c.key, variant="protected", outcome="error", rejected_by=str(e), note="")
            rows.append(row); seen[c.emu_test] = row
            continue
        last = [l for l in out.splitlines() if "checks passed" in l]
        passed = last and last[-1].split("/")[0].strip().isdigit() and \
            last[-1].split("/")[0].strip() == last[-1].split("/")[1].split()[0]
        outcome = "rejected" if passed else "FAILED"
        row = dict(cls=c.key, variant="protected", outcome=outcome, rejected_by=c.rejected_by,
                   note=last[-1] if last else "no result line", emu_test=c.emu_test)
        rows.append(row); seen[c.emu_test] = row
        if runner is not None:
            runner.record(c.key, "protected", outcome, c.rejected_by, note=row["note"])
    return rows


def summary(results: List[dict]) -> dict:
    prot = [r for r in results if r["variant"] == "protected"]
    return dict(classes=len(CATALOGUE), run=len([r for r in prot if r["outcome"] != "not run"]),
                rejected=len([r for r in prot if r["outcome"] == "rejected"]),
                findings=len([r for r in prot if r["outcome"].startswith("finding")]),
                not_run=len([r for r in prot if r["outcome"] == "not run"]))


if __name__ == "__main__":
    for c in CATALOGUE:
        print(f"{c.key:26s} {c.layer:9s} plugin {c.plugin or '-':12s} needs {c.needs}")

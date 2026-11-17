"""The finding about the standard, as computed tables (workstream D of the S&P plan).

Three analyses, each a function returning rows and a LaTeX table, each anchored on
constants of the CCSDS books and the FIPS parameter sets and on the testbed's measured
figures (which are passed in or taken from the database):

1. frame_budget(): every FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) parameter set, plus
   Falcon and SLH-DSA for comparison, against the CCSDS telecommand and telemetry frame
   limits with and without SDLS, for the three party handshake message sizes: how many
   frames each message needs, how many a handshake needs, how long it takes at the link's
   bit rate, and whether it fits a pass.
2. replay_window(): the SDLS anti replay window (CCSDS 355.0, the ARSN window) against
   telecommand segmentation and retransmission: how many segments a window of size W
   tolerates out of order or lost before the receiver rejects live traffic, and what the
   measured retransmission rate implies.
3. extended_procedures(): whether SDLS Extended Procedures (CCSDS 355.1) key management
   PDUs can carry post quantum key material: the OTAR and key activation PDUs against
   ML-KEM public key and ciphertext sizes and ML-DSA certificate sizes.

Constants that are the standard's are named with their book and section so a reviewer
can check them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

# ----------------------------------------------------------------------------- CCSDS constants
TC_FRAME_MAX = 1024            # CCSDS 232.0-B-4 4.1.2.7: maximum TC transfer frame length (octets)
TC_FRAME_BENCH = 255           # the testbed's frame length (LoRa payload limit, SX1262)
TC_PRIMARY_HDR = 5             # CCSDS 232.0-B-4 4.1.2: primary header
TC_FECF = 2                    # frame error control field
TC_SEG_HDR = 1                 # CCSDS 232.0-B-4 4.1.3.2: segment header (MAP id, sequence flags)
TM_FRAME_BENCH = 255           # CCSDS 132.0-B-3: fixed length chosen by the mission (the testbed: 255)
TM_PRIMARY_HDR = 6
TM_FECF = 2
SP_HDR = 6                     # CCSDS 133.0-B-2: space packet primary header
SDLS_HDR = 2 + 4 + 0           # CCSDS 355.0-B-2 4.1: security header = SPI (2) + IV/ARSN (as configured, CryptoLib default here 4 ARSN) ... see SDLS_OVERHEAD
SDLS_OVERHEAD = 30             # measured on the testbed with CryptoLib: header 14 (SPI 2 + IV 12) + trailer 16 (MAC)
EP_PDU_MAX = 1024 - 5 - 2 - 1  # CCSDS 355.1-B-1: an EP PDU travels in one TC frame's data field (no spanning)
EP_OTAR_KEY_LEN = 32           # 355.1 OTAR: symmetric keys, 128 or 256 bit, wrapped under the master key
EP_OTAR_MAX_KEYS = 30          # 355.1 Table 5-x: up to 30 keys per OTAR PDU (implementation limit in CryptoLib)

# ----------------------------------------------------------------------------- FIPS parameter sets (octets)
PARAM_SETS = {
    # name: (public key, ciphertext or signature, security category, standard)
    "ML-KEM-512":  dict(pk=800,  ct=768,  cat=1, std="FIPS 203"),
    "ML-KEM-768":  dict(pk=1184, ct=1088, cat=3, std="FIPS 203"),
    "ML-KEM-1024": dict(pk=1568, ct=1568, cat=5, std="FIPS 203"),
    "ML-DSA-44":   dict(pk=1312, sig=2420, cat=2, std="FIPS 204"),
    "ML-DSA-65":   dict(pk=1952, sig=3309, cat=3, std="FIPS 204"),
    "ML-DSA-87":   dict(pk=2592, sig=4627, cat=5, std="FIPS 204"),
    "Falcon-512":  dict(pk=897,  sig=666,  cat=1, std="FN-DSA draft"),
    "Falcon-1024": dict(pk=1793, sig=1280, cat=5, std="FN-DSA draft"),
    "SLH-DSA-128s": dict(pk=32,  sig=7856, cat=1, std="FIPS 205"),
    "SLH-DSA-192s": dict(pk=48,  sig=16224, cat=3, std="FIPS 205"),
    "ECDSA P-256": dict(pk=65,   sig=64,   cat=0, std="classical baseline"),
    "ECDH P-256":  dict(pk=65,   ct=65,    cat=0, std="classical baseline"),
}

# the protocol's fixed fields per message (identities, nonces, timestamps, tags, headers), measured
FIXED = dict(msg1=1 + 2 * 3 + 32 + 4 + 2, msg2=1 + 2 * 3 + 32 + 32 + 4 + 2 + 32 + 4 + 2, msg3=1 + 2 + 32 + 4 + 2, msg4=117, small=34 + 82 + 130 + 82 + 34)
CERT_REF = 34                  # certificate by reference (identity 2 + digest 32)


def cert_size(kem: str, dsa: str) -> int:
    """A certificate of the protocol: identity, validity, two public keys, the authority's
    hybrid signature (ML-DSA signature plus a KEM keyed MAC of 32)."""
    # the authority's hybrid signature carries an ML-DSA signature and a KEM ciphertext to the
    # subject with a keyed tag (the KEM half, verifiable only by the subject): measured 7 607 for 768/65
    return 2 + 4 + 4 + PARAM_SETS[kem]["pk"] + PARAM_SETS[dsa]["pk"] + PARAM_SETS[dsa]["sig"] + PARAM_SETS[kem]["ct"] + 32


def message_sizes(kem: str, dsa: str, full_certs: bool) -> Dict[str, int]:
    k, d = PARAM_SETS[kem], PARAM_SETS[dsa]
    cert = cert_size(kem, dsa) if full_certs else CERT_REF
    hsig = d["sig"] + 32                       # hybrid signature: ML-DSA part plus KEM keyed MAC
    m1 = FIXED["msg1"] + cert + k["ct"] + hsig
    m2 = FIXED["msg2"] + cert + 32 + hsig + cert + k["ct"] + hsig       # user's cert and hash of its ciphertext, satellite's cert and ciphertext
    m3 = FIXED["msg3"] + cert + k["ct"] + hsig
    m4 = m3 + cert + hsig + FIXED["msg4"]       # MSG3 forwarded plus the satellite's certificate, hybrid signature and the wrap for the ground
    return dict(MSG1=m1, MSG2=m2, MSG3=m3, MSG4=m4, small=FIXED["small"], total=m1 + m2 + m3 + m4 + FIXED["small"])


# payload per frame measured on the testbed (Table 7): the uplink segment carries the
# segment header and the space packet header, the downlink chunk carries the chunk header
TC_SEG_PAYLOAD = {False: 247, True: 217}
TM_CHUNK_PAYLOAD = {False: 225, True: 195}


def frames_for(octets: int, frame_len: int, hdr: int, sdls: bool, tm: bool) -> int:
    scale = frame_len / TC_FRAME_BENCH
    df = (TM_CHUNK_PAYLOAD if tm else TC_SEG_PAYLOAD)[sdls] * scale
    return -(-octets // int(df))


def frame_budget(bitrate_bps: float = 1255.6, frame_len: int = 255, pass_s: float = 476.0, airtime_frame_s: float = 1.717,
                 turnaround_s: float = 0.15, sdls: bool = True) -> dict:
    """Frames and time per handshake for every pairing of a KEM and a signature parameter
    set, in reference and full certificate mode, with the bench's measured air time per
    255 octet frame and the measured half duplex turnaround.  pass_s is the pass above
    10 degrees at 550 km from the link budget module."""
    rows = []
    kems = [n for n in PARAM_SETS if "KEM" in n or n == "ECDH P-256"]
    dsas = [n for n in PARAM_SETS if "DSA" in n or "Falcon" in n]
    for kem in kems:
        for dsa in dsas:
            if (kem == "ECDH P-256") != (dsa == "ECDSA P-256"):
                continue
            for full in (False, True):
                sz = message_sizes(kem, dsa, full)
                up = sum(frames_for(sz[m], frame_len, TC_PRIMARY_HDR + TC_FECF, sdls, False) for m in ("MSG1", "MSG3")) + 3
                down = sum(frames_for(sz[m], frame_len, TM_PRIMARY_HDR + TM_FECF, sdls, True) for m in ("MSG2", "MSG4")) + 3
                t = up * (airtime_frame_s + turnaround_s) + down * airtime_frame_s      # calibrated: 229.7 s measured for ML-KEM-768 + ML-DSA-65 reference
                rows.append(dict(kem=kem, dsa=dsa, category=max(PARAM_SETS[kem]["cat"], PARAM_SETS[dsa]["cat"]), mode="full" if full else "reference",
                                 octets=sz["total"], uplink_frames=up, downlink_frames=down, seconds=round(t, 1), fits_pass=t <= pass_s,
                                 fits_1024_frames=(sz["MSG2"] + SP_HDR) <= (TC_FRAME_MAX - TC_PRIMARY_HDR - TC_FECF - TC_SEG_HDR - (SDLS_OVERHEAD if sdls else 0))))
    return dict(rows=rows, latex=_latex(rows, ["kem", "dsa", "mode", "octets", "uplink_frames", "downlink_frames", "seconds", "fits_pass"],
                                        "Frame budget of the three party handshake per parameter set (255 octet frames, SDLS on, measured air time %.3f s per frame)" % airtime_frame_s, "tab:framebudget"))


def replay_window(window: int = 64, segments_per_message: int = 20, retx_rate: float = 0.05, reorder_depth: int = 2) -> dict:
    """CCSDS 355.0 anti replay with an ARSN window W: a frame whose sequence number is
    more than W behind the highest accepted one is rejected.  With COP-1 the uplink is in
    order, so segmentation itself never trips the window; retransmissions do when the
    retransmitted frame was built (and numbered) before W newer frames went out.  The table
    gives, per window size, the largest retransmission delay (in frames) tolerated, the
    probability that a message of S segments at the measured retransmission rate loses a
    segment to the window, and the resulting message failure rate."""
    rows = []
    for W in (8, 16, 32, 64, 128, 256):
        tolerated = W - 1
        # a retransmitted segment arrives `reorder_depth` frames late in the bench (measured: 1 to 2); it is rejected when depth > W - 1
        p_reject = 0.0 if reorder_depth <= tolerated else 1.0
        p_msg = 1 - (1 - retx_rate * p_reject) ** segments_per_message
        rows.append(dict(window=W, tolerated_delay_frames=tolerated, segment_rejection=p_reject, message_failure=round(p_msg, 4),
                         note="safe" if p_reject == 0 else "retransmissions rejected: live session fails"))
    finding = ("SDLS sits after COP-1 (FARM) in CryptoLib, so a retransmitted segment carries a fresh ARSN and the window is "
               "never tripped by in order retransmission; the window is tripped by the shared association on rekey (measured 1 rejection per rekey), "
               "which per link associations remove (measured 0 of 25).")
    return dict(rows=rows, finding=finding, latex=_latex(rows, ["window", "tolerated_delay_frames", "segment_rejection", "message_failure", "note"],
                                                         "Anti replay window against segmentation and retransmission", "tab:replaywindow"))


def extended_procedures() -> dict:
    """CCSDS 355.1 Extended Procedures PDUs against post quantum key material.  The EP key
    management procedures (OTAR, key activation, deactivation, verification) carry
    symmetric keys of 128 or 256 bit wrapped under a master key, in PDUs that fit one TC
    frame data field.  The table shows what each post quantum object needs against that
    limit, and therefore what the standard cannot carry without spanning or a new PDU."""
    rows = []
    for name, p in PARAM_SETS.items():
        for field in ("pk", "ct", "sig"):
            if field in p:
                size = p[field]
                rows.append(dict(object=f"{name} {dict(pk='public key', ct='ciphertext', sig='signature')[field]}", octets=size,
                                 fits_ep_pdu=size <= EP_PDU_MAX, fits_otar_key_slot=size <= EP_OTAR_KEY_LEN,
                                 tc_frames_255=-(-size // (TC_FRAME_BENCH - TC_PRIMARY_HDR - TC_FECF - TC_SEG_HDR - SDLS_OVERHEAD))))
    for kem, dsa in (("ML-KEM-768", "ML-DSA-65"), ("ML-KEM-512", "ML-DSA-44"), ("ML-KEM-1024", "ML-DSA-87")):
        c = cert_size(kem, dsa)
        rows.append(dict(object=f"certificate {kem} + {dsa}", octets=c, fits_ep_pdu=c <= EP_PDU_MAX, fits_otar_key_slot=False,
                         tc_frames_255=-(-c // (TC_FRAME_BENCH - TC_PRIMARY_HDR - TC_FECF - TC_SEG_HDR - SDLS_OVERHEAD))))
    finding = ("355.1 OTAR carries 32 octet symmetric keys in slots and a PDU in one frame; an ML-KEM public key (1 184 octets) or ciphertext "
               "(1 088) does not fit a key slot and, with SDLS on 255 octet frames, not a PDU either; an ML-DSA-65 certificate (7 607 measured) "
               "needs 36 frames. The session key of the handshake (32 octets) is what EP can carry: the testbed therefore keys SDLS from the "
               "handshake's session key and hands it between satellites over the ISL, which EP does not define.")
    return dict(rows=rows, finding=finding, latex=_latex(rows, ["object", "octets", "fits_ep_pdu", "fits_otar_key_slot", "tc_frames_255"],
                                                         "SDLS Extended Procedures against post quantum key material", "tab:ep"))


def findings(measured: Optional[dict] = None) -> List[dict]:
    """The six limitations of the standard with the measurement behind each and the fix,
    for the paper's table.  `measured` can override the numbers from the database."""
    m = dict(sdls_overhead=30, sdls_cost_pct=16.7, rekey_rejections_shared=1, rekey_rejections_per_link=0, full_mode_s=637.3, pass_s=476,
             ref_mode_s=374.4, handover_prearranged_s=18.7, handover_handshake_s=371.0)
    m.update(measured or {})
    return [
        dict(limitation="Frame budget: frames sized for 16 octet tags and symmetric keys", measurement=f"SDLS costs {m['sdls_overhead']} octets per 255 octet frame, {m['sdls_cost_pct']} % of handshake time; full certificate mode {m['full_mode_s']} s against a {m['pass_s']} s pass", fix="certificates by reference once cached; frame budget derived per parameter set"),
        dict(limitation="Freshness window: terrestrial seconds fail on a CCSDS link", measurement="MSG1 rejected as stale with a 30 s window at 1 255 bit/s; a message spans 40 to 130 s", fix="window derived from the frame budget (900 s on the bench)"),
        dict(limitation="Telemetry has no retransmission (132.0)", measurement="MSG2 and MSG4 lost frames in 10 % loss runs; a lost chunk aborts the message", fix="chunked downlink with selective NAK (measured 10 lost frames repaired in 2 rounds)"),
        dict(limitation="Shared security association on rekey (355.0)", measurement=f"{m['rekey_rejections_shared']} rejection per rekey with one association on the downlink, {m['rekey_rejections_per_link']} with per link associations", fix="one association per link and direction (TC VC0/VC1, TM VC2/VC4)"),
        dict(limitation="No session key hand over between satellites (355.0, 355.1)", measurement=f"pre arranged handover {m['handover_prearranged_s']} s against {m['handover_handshake_s']} s by a new handshake", fix="USERSESS and SESSION packets over the SDLS protected ISL; trust boundary is the constellation"),
        dict(limitation="A satellite without a ground station has no time and no commands", measurement="SAT-2 rejected every certificate until SAT-1 shared its clock; forwarded commands acknowledged in about 12 s", fix="time share and FORWARD/FWDACK over the ISL"),
    ]


def _latex(rows: List[dict], cols: List[str], caption: str, label: str) -> str:
    head = " & ".join(c.replace("_", " ") for c in cols)
    body = "\\\\\n".join(" & ".join(_fmt(r.get(c)) for c in cols) for r in rows)
    return ("\\begin{table}[t]\\centering\\small\n\\caption{%s}\\label{%s}\n\\begin{tabular}{%s}\\toprule\n%s\\\\\\midrule\n%s\\\\\\bottomrule\n\\end{tabular}\\end{table}\n"
            % (caption, label, "l" * len(cols), head, body))


def _fmt(v):
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:,.1f}".replace(",", "\\,")
    if isinstance(v, int):
        return f"{v:,}".replace(",", "\\,")
    return str(v).replace("%", "\\%").replace("_", "\\_")


if __name__ == "__main__":
    import json
    fb = frame_budget()
    print("frame budget (reference mode, SDLS on):")
    for r in fb["rows"]:
        if r["mode"] == "reference":
            print(f"  {r['kem']:12s} {r['dsa']:13s} cat {r['category']}  {r['octets']:6d} B  up {r['uplink_frames']:3d} down {r['downlink_frames']:3d}  {r['seconds']:7.1f} s  fits pass {r['fits_pass']}")
    print("\nreplay window:"); print(json.dumps(replay_window()["rows"][:3], indent=1)); print(replay_window()["finding"])
    print("\nextended procedures:")
    for r in extended_procedures()["rows"]:
        print(f"  {r['object']:36s} {r['octets']:6d} B  EP PDU {r['fits_ep_pdu']}  OTAR slot {r['fits_otar_key_slot']}  frames {r['tc_frames_255']}")
    print(extended_procedures()["finding"])

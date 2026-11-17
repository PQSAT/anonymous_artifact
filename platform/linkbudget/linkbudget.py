#!/usr/bin/env python3
"""
Link budget, Doppler and delay calculator for the PQSAT bench constellation
testbed (LILYGO T-Beam S3, SX1262 LoRa at 868 MHz) and for the LEO link
that the bench emulates.

Only the math module is used. Every number quoted in LINK_BUDGET.md is
produced by this script. Run:  python3 linkbudget.py
"""

import math

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
C = 299_792_458.0            # speed of light, m/s
R_E = 6371.0e3               # mean Earth radius, m
MU = 3.986004418e14          # Earth gravitational parameter, m^3/s^2

# ---------------------------------------------------------------------------
# Radio parameters (bench configuration)
# ---------------------------------------------------------------------------
F_UHF = 868.0e6              # LoRa carrier, Hz
F_SBAND = 2.2e9              # S band comparison carrier, Hz
BW = 125.0e3                 # LoRa bandwidth, Hz
CR_NUM, CR_DEN = 4, 7        # coding rate 4/7
SF_USED = 9
P_TX_DBM = 14.0              # transmit power actually used
P_TX_MAX_DBM = 22.0          # T-Beam S3 maximum
NF_DB = 6.0                  # SX1262 noise figure

# Typical SX1262 sensitivity at 125 kHz bandwidth (dBm), Semtech datasheet
# values rounded; SF9 is the figure quoted in the brief (-129 dBm).
SENS_DBM = {7: -124.0, 8: -127.0, 9: -129.0, 10: -132.0, 11: -134.5, 12: -137.0}

# Antenna gains
G_BENCH_DBI = 2.0            # stock whip on each T-Beam
G_SAT_DBI = 6.0              # satellite patch
G_GND_DBI = 12.0             # ground Yagi
L_POL_DB = 2.0               # polarisation mismatch
L_ATM_DB = 1.0               # atmospheric and ionospheric loss at UHF

# Frame air times measured on the bench (SF9, 125 kHz, CR 4/7, preamble 8)
AIRTIME_S = {255: 1.717, 60: 0.484, 20: 0.226}

# Measured bench timings (seconds)
RTT_PING_S = 0.570
RTT_SEG_MIN_S, RTT_SEG_MAX_S = 1.3, 1.9
SAT_TURNAROUND_S = 0.150
HANDSHAKE_S = {"reference mode, one satellite, clear link": 332.8,
               "reference mode, two satellites and RF ISL, under SDLS": 546.8,
               "full certificates, two satellites and RF ISL": 900.4}
RSSI_BENCH_DBM = (-18.0, -40.0)

# ---------------------------------------------------------------------------
# Formulas
# ---------------------------------------------------------------------------

def fspl_db(d_m, f_hz):
    """Free space path loss.  FSPL = 20 log10(4 pi d f / c)."""
    return 20.0 * math.log10(4.0 * math.pi * d_m * f_hz / C)


def rx_power_dbm(p_tx_dbm, g_tx_dbi, g_rx_dbi, path_loss_db, other_loss_db=0.0):
    """Friis in dB form.  Pr = Pt + Gt + Gr - FSPL - other losses."""
    return p_tx_dbm + g_tx_dbi + g_rx_dbi - path_loss_db - other_loss_db


def lora_bitrate(sf, bw_hz, cr_num, cr_den):
    """LoRa physical bit rate.  Rb = SF * BW / 2^SF * (cr_num / cr_den)."""
    return sf * bw_hz / (2 ** sf) * (cr_num / cr_den)


def orbital_velocity(h_m):
    """Circular orbit speed.  v = sqrt(mu / (R_E + h))."""
    return math.sqrt(MU / (R_E + h_m))


def slant_range(h_m, el_deg):
    """Slant range from ground station to satellite at elevation el.
    d = sqrt((R_E + h)^2 - (R_E cos el)^2) - R_E sin el
    """
    el = math.radians(el_deg)
    return math.sqrt((R_E + h_m) ** 2 - (R_E * math.cos(el)) ** 2) - R_E * math.sin(el)


def nadir_angle(h_m, el_deg):
    """Angle at the satellite between nadir and the ground station.
    sin(theta) = R_E cos(el) / (R_E + h)
    """
    el = math.radians(el_deg)
    return math.asin(R_E * math.cos(el) / (R_E + h_m))


def doppler_shift(h_m, el_deg, f_hz):
    """Line of sight Doppler for an in plane (overhead) pass.
    v_r = v sin(theta) = v R_E cos(el) / (R_E + h)
    f_d = f v_r / c
    Maximum is at el = 0 (horizon).
    """
    v = orbital_velocity(h_m)
    v_r = v * math.sin(nadir_angle(h_m, el_deg))
    return f_hz * v_r / C


def doppler_rate_max(h_m, f_hz):
    """Maximum Doppler rate, at the zenith of an overhead pass.
    df/dt = (f / c) * v^2 / h
    """
    v = orbital_velocity(h_m)
    return (f_hz / C) * v * v / h_m


def one_way_delay(d_m):
    """Propagation delay.  t = d / c."""
    return d_m / C


def pass_duration(h_m, el_min_deg):
    """Duration of an overhead pass above el_min, Earth rotation ignored.
    Earth central angle at el_min:  beta = acos(R_E cos(el) / (R_E + h)) - el
    Angular rate of satellite:      omega = v / (R_E + h)
    Duration:                       T = 2 beta / omega
    """
    el = math.radians(el_min_deg)
    beta = math.acos(R_E * math.cos(el) / (R_E + h_m)) - el
    omega = orbital_velocity(h_m) / (R_E + h_m)
    return 2.0 * beta / omega


def range_for_loss(loss_db, f_hz):
    """Invert FSPL.  d = c / (4 pi f) * 10^(loss / 20)."""
    return C / (4.0 * math.pi * f_hz) * 10 ** (loss_db / 20.0)


def noise_floor_dbm(bw_hz, nf_db):
    """Thermal noise.  N = -174 dBm/Hz + 10 log10(BW) + NF."""
    return -174.0 + 10.0 * math.log10(bw_hz) + nf_db


# ---------------------------------------------------------------------------
# Printing helpers
# ---------------------------------------------------------------------------

def table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    line = " | ".join(str(h).ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(" | ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    print()


def main():
    print("=" * 78)
    print("PQSAT bench constellation testbed: link budget, Doppler and delay")
    print("=" * 78)
    print()

    # --- 0. LoRa physical layer ------------------------------------------
    print("0. LoRa physical bit rate, BW 125 kHz, CR 4/7")
    rows = []
    for sf in range(7, 13):
        rows.append([f"SF{sf}", f"{lora_bitrate(sf, BW, CR_NUM, CR_DEN):8.1f}", f"{SENS_DBM[sf]:7.1f}"])
    table(["SF", "bit/s", "sens dBm"], rows)
    nf = noise_floor_dbm(BW, NF_DB)
    print(f"Thermal noise floor in 125 kHz with NF {NF_DB:.0f} dB: {nf:.1f} dBm")
    print(f"Implied SNR at SF9 sensitivity: {SENS_DBM[9] - nf:.1f} dB")
    print()

    # --- 1. Bench link budget --------------------------------------------
    print("1. Bench link budget at 868 MHz, 14 dBm, 2 dBi + 2 dBi")
    rows = []
    bench = {}
    for d in (1.0, 2.0, 3.0):
        L = fspl_db(d, F_UHF)
        pr = rx_power_dbm(P_TX_DBM, G_BENCH_DBI, G_BENCH_DBI, L)
        m = pr - SENS_DBM[SF_USED]
        bench[d] = (L, pr, m)
        rows.append([f"{d:.0f} m", f"{L:6.1f}", f"{pr:7.1f}", f"{m:6.1f}"])
    table(["distance", "FSPL dB", "Pr dBm", "margin dB vs -129"], rows)
    print(f"Measured bench RSSI: {RSSI_BENCH_DBM[0]:.0f} to {RSSI_BENCH_DBM[1]:.0f} dBm")
    print(f"Margin of measured RSSI over sensitivity: "
          f"{RSSI_BENCH_DBM[0] - SENS_DBM[9]:.0f} to {RSSI_BENCH_DBM[1] - SENS_DBM[9]:.0f} dB")
    print()

    # --- 2. Orbit link budget --------------------------------------------
    print("2. Orbit to ground geometry and link budget")
    orbit = {}
    rows = []
    for h_km in (550, 1200):
        for el in (10, 30, 90):
            d = slant_range(h_km * 1e3, el)
            L_u = fspl_db(d, F_UHF)
            L_s = fspl_db(d, F_SBAND)
            pr = rx_power_dbm(P_TX_DBM, G_SAT_DBI, G_GND_DBI, L_u, L_POL_DB + L_ATM_DB)
            m9 = pr - SENS_DBM[9]
            t1 = one_way_delay(d)
            orbit[(h_km, el)] = dict(d=d, L_u=L_u, L_s=L_s, pr=pr, m9=m9, t1=t1)
            rows.append([f"{h_km}", f"{el:2d}", f"{d/1e3:7.0f}", f"{L_u:6.1f}", f"{L_s:6.1f}",
                         f"{pr:7.1f}", f"{m9:6.1f}", f"{t1*1e3:5.2f}", f"{2*t1*1e3:5.2f}"])
    table(["h km", "el", "range km", "FSPL 868", "FSPL 2.2G", "Pr dBm", "SF9 margin",
           "1 way ms", "RTT ms"], rows)
    print(f"S band penalty relative to 868 MHz: {20*math.log10(F_SBAND/F_UHF):.2f} dB")
    print()

    print("2b. Margin per spreading factor at 14 dBm (dB), 868 MHz")
    rows = []
    for h_km in (550, 1200):
        for el in (10, 30, 90):
            pr = orbit[(h_km, el)]["pr"]
            rows.append([f"{h_km}", f"{el:2d}"] + [f"{pr - SENS_DBM[sf]:6.1f}" for sf in range(7, 13)])
    table(["h km", "el", "SF7", "SF8", "SF9", "SF10", "SF11", "SF12"], rows)

    print("2c. Same with the ground station at 27 dBm (869.4 to 869.65 MHz uplink)")
    rows = []
    for h_km in (550, 1200):
        for el in (10, 30, 90):
            pr = orbit[(h_km, el)]["pr"] + (27.0 - P_TX_DBM)
            rows.append([f"{h_km}", f"{el:2d}", f"{pr:7.1f}"] +
                        [f"{pr - SENS_DBM[sf]:6.1f}" for sf in (9, 10, 11, 12)])
    table(["h km", "el", "Pr dBm", "SF9", "SF10", "SF11", "SF12"], rows)

    # Attenuation needed to turn the bench into an orbit link
    print("2d. Attenuation needed to emulate the orbit link on the bench")
    rows = []
    for h_km in (550, 1200):
        for el in (10, 90):
            target = orbit[(h_km, el)]["pr"]
            rows.append([f"{h_km}", f"{el:2d}", f"{target:7.1f}",
                         f"{bench[1.0][1] - target:5.0f}", f"{bench[3.0][1] - target:5.0f}",
                         f"{RSSI_BENCH_DBM[0] - target:5.0f}", f"{RSSI_BENCH_DBM[1] - target:5.0f}"])
    table(["h km", "el", "orbit Pr dBm", "from calc 1 m", "from calc 3 m",
           "from meas -18", "from meas -40"], rows)

    # --- 3. Doppler --------------------------------------------------------
    print("3. Doppler")
    rows = []
    dop = {}
    for h_km in (550, 1200):
        v = orbital_velocity(h_km * 1e3)
        fd_u = doppler_shift(h_km * 1e3, 0.0, F_UHF)
        fd_s = doppler_shift(h_km * 1e3, 0.0, F_SBAND)
        rate_u = doppler_rate_max(h_km * 1e3, F_UHF)
        rate_s = doppler_rate_max(h_km * 1e3, F_SBAND)
        dop[h_km] = dict(v=v, fd_u=fd_u, fd_s=fd_s, rate_u=rate_u, rate_s=rate_s)
        rows.append([f"{h_km}", f"{v:7.0f}", f"{fd_u/1e3:6.1f}", f"{fd_s/1e3:6.1f}",
                     f"{rate_u:6.0f}", f"{rate_s:6.0f}",
                     f"{rate_u*AIRTIME_S[255]:6.0f}", f"{rate_s*AIRTIME_S[255]:6.0f}"])
    table(["h km", "v m/s", "max fd kHz 868", "max fd kHz 2.2G",
           "rate Hz/s 868", "rate Hz/s 2.2G", "drift/frame 868", "drift/frame 2.2G"], rows)
    tol = 0.25 * BW
    print(f"SX1262 tolerated offset, 25 percent of BW: {tol/1e3:.2f} kHz")
    for h_km in (550, 1200):
        print(f"  {h_km} km: 868 MHz max shift {dop[h_km]['fd_u']/1e3:.1f} kHz "
              f"({'inside' if dop[h_km]['fd_u'] < tol else 'OUTSIDE'} tolerance); "
              f"2.2 GHz max shift {dop[h_km]['fd_s']/1e3:.1f} kHz "
              f"({'inside' if dop[h_km]['fd_s'] < tol else 'OUTSIDE'} tolerance)")
    print()
    print("3b. Doppler shift against elevation, 550 km, 868 MHz")
    rows = [[f"{el:2d}", f"{doppler_shift(550e3, el, F_UHF)/1e3:6.1f}",
             f"{doppler_shift(550e3, el, F_SBAND)/1e3:6.1f}"] for el in (0, 10, 30, 60, 90)]
    table(["el", "fd kHz 868", "fd kHz 2.2G"], rows)

    # --- 4. Delay and timing ------------------------------------------------
    print("4. Propagation delay against bench timing")
    rows = []
    for el in (10, 30, 90):
        t1 = orbit[(550, el)]["t1"]
        rows.append([f"{el:2d}", f"{t1*1e3:5.2f}", f"{2*t1*1e3:5.2f}",
                     f"{RTT_PING_S*1e3:.0f}", f"{2*t1/RTT_PING_S*100:4.1f}"])
    table(["el", "1 way ms", "RTT ms", "bench PING RTT ms", "orbit RTT as % of bench"], rows)
    air2 = AIRTIME_S[20] * 2
    print(f"PING RTT composition: two 20 octet frames on air = {air2*1e3:.0f} ms "
          f"({air2/RTT_PING_S*100:.0f} % of the measured {RTT_PING_S*1e3:.0f} ms); "
          f"air time plus {SAT_TURNAROUND_S*1e3:.0f} ms turnaround = {(air2+SAT_TURNAROUND_S)*1e3:.0f} ms, "
          f"which already covers the measured RTT (the reply frame is shorter than 20 octets).")
    print(f"Orbit propagation adds at most {2*orbit[(550,10)]['t1']*1e3:.1f} ms per hop at 550 km, "
          f"{2*orbit[(1200,10)]['t1']*1e3:.1f} ms at 1200 km.")
    print(f"Segment RTT measured {RTT_SEG_MIN_S:.1f} to {RTT_SEG_MAX_S:.1f} s; "
          f"255 octet frame air time {AIRTIME_S[255]*1e3:.0f} ms, 60 octet ack {AIRTIME_S[60]*1e3:.0f} ms, "
          f"sum {(AIRTIME_S[255]+AIRTIME_S[60])*1e3:.0f} ms.")
    print()
    T = pass_duration(550e3, 10)
    T1200 = pass_duration(1200e3, 10)
    print(f"Overhead pass above 10 degrees: 550 km {T:.0f} s ({T/60:.1f} min), "
          f"1200 km {T1200:.0f} s ({T1200/60:.1f} min)")
    rows = []
    for name, t in HANDSHAKE_S.items():
        rows.append([name, f"{t:.0f}", f"{t/T*100:5.0f}",
                     "yes" if t < T else "no", "yes" if t < 600 else "no"])
    table(["handshake", "s", "% of 550 km pass", "fits computed pass", "fits 10 min"], rows)

    # --- 5. Ground range ----------------------------------------------------
    print("5. Free space range of the bench radio on the ground, 14 dBm, 2 dBi + 2 dBi")
    rows = []
    for sf in (7, 9, 12):
        for fade in (0.0, 10.0, 20.0):
            allowed = P_TX_DBM + 2 * G_BENCH_DBI - SENS_DBM[sf] - fade
            rows.append([f"SF{sf}", f"{fade:.0f}", f"{allowed:.1f}", f"{range_for_loss(allowed, F_UHF)/1e3:7.1f}"])
    table(["SF", "fade margin dB", "allowed loss dB", "range km"], rows)
    print("Figures are free space; real terrestrial range is terrain limited, typically a few km.")
    print()


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------- used by the orbit layer
def margin_db(distance_km, profile="SF11", f_hz=F_UHF, p_tx_dbm=P_TX_DBM, g_tx_dbi=G_SAT_DBI, g_rx_dbi=G_GND_DBI):
    """Link margin at a slant range for a LoRa spreading factor profile ("SF7".."SF12"),
    with the orbit antennas (satellite patch, ground Yagi) and the fixed losses above."""
    sf = int(str(profile).upper().replace("SF", "")) if str(profile).upper().startswith("SF") else SF_USED
    loss = fspl_db(distance_km * 1000.0, f_hz) + L_POL_DB + L_ATM_DB
    return rx_power_dbm(p_tx_dbm, g_tx_dbi, g_rx_dbi, loss) - SENS_DBM.get(sf, SENS_DBM[SF_USED])


def required_sf(distance_km, min_margin_db=3.0, **kw):
    """The lowest spreading factor that closes the link with the margin, or None."""
    for sf in range(7, 13):
        if margin_db(distance_km, f"SF{sf}", **kw) >= min_margin_db:
            return sf
    return None

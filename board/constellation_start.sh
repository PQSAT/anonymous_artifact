#!/bin/sh
# Constellation start script: SAT-1 (cpu1) and SAT-2 (cpu2) on the one Versal, joined by
# the inter satellite link, sharing the console UART to the laptop bridge through sat_mux.
# Run from the SD card after login:   sudo -i ; sh /run/media/mmcblk0p1/constellation_start.sh
#   sh constellation_start.sh          inter satellite link on board (Unix socket), as before
#   sh constellation_start.sh rf       inter satellite link on the four 433 MHz radios, full duplex
#   sh constellation_start.sh check    install, run SAT-2 for 20 s in the foreground, hand nothing over
# sat_protocol_upgrade.tgz (the flight application with the authentication protocol, and the
# certificates and keys of this board) is applied when it is on the card.
set -e
SD=/run/media/mmcblk0p1
cd /root

if [ "$(date +%Y)" -lt 2026 ]; then
    T=$(stat -c %Y $SD/sat_constellation_upgrade.tgz 2>/dev/null)
    if [ -n "$T" ] && [ "$T" -gt 1780000000 ]; then
        date -s "@$T" >/dev/null && echo "clock set from SD card: $(date -u)"
    fi
fi
systemctl stop sat1-handover.service sat1.service sat2.service satmux.service 2>/dev/null || true
if [ ! -x /root/cpu1/core-cpu1 ]; then
    echo "installing flight software"
    tar xzf $SD/sat1_cfs_rf.tgz
fi
if [ -f $SD/sat1_pqc_upgrade.tgz ]; then
    echo "applying PQC upgrade (sat_rf.so, libpqsat.so, auth keys)"
    tar xzf $SD/sat1_pqc_upgrade.tgz
fi
if [ -x /root/cpu1/pqsat_selftest ]; then
    (cd /root/cpu1 && LD_LIBRARY_PATH=/root/cpu1 ./pqsat_selftest > /root/cpu1/pqsat_selftest.log 2>&1) || true
    tail -1 /root/cpu1/pqsat_selftest.log
fi
echo "applying constellation upgrade (SAT-1 sat_rf.so with ISL, SAT-2 instance, sat_mux, ISL key)"
tar xzf $SD/sat_constellation_upgrade.tgz
if [ -f $SD/sat_protocol_upgrade.tgz ]; then
    echo "applying the protocol package (sat_rf.so, certificates and keys of this board)"
    tar xzf $SD/sat_protocol_upgrade.tgz
fi
chmod +x /root/sat_mux /root/cpu2/core-cpu2
cp /root/cpu1/libgcc_s.so.1 /lib/ 2>/dev/null || true

# one UART, two satellites: sat_mux owns /dev/ttyAMA0 and offers /tmp/sat1.tty and /tmp/sat2.tty
cat > /etc/systemd/system/satmux.service <<'UNIT'
[Unit]
Description=Serial multiplexer for the two satellite instances

[Service]
Type=simple
ExecStart=/root/sat_mux /dev/ttyAMA0 /tmp/sat1.tty /tmp/sat2.tty
Restart=always
RestartSec=2
UNIT

cat > /etc/systemd/system/sat1.service <<'UNIT'
[Unit]
Description=SAT-1 flight software (feeder satellite: ground station on its radio)
Requires=satmux.service
After=satmux.service

[Service]
Type=simple
WorkingDirectory=/root/cpu1
Environment=SAT_RF_DEVICE=/tmp/sat1.tty
Environment=LD_LIBRARY_PATH=/root/cpu1
Environment=SAT_AUTH_DIR=/root/cpu1/auth
Environment=SAT_AUTH_FRESH_S=900
Environment=SAT_SCID=0x101
Environment=SAT_ISL_PEER=0x102
Environment=SAT_ISL_KEY=/root/cpu1/auth/isl_sat1_sat2.key
ExecStartPre=/bin/sh -c 'echo 256 > /proc/sys/fs/mqueue/msg_max'
ExecStartPre=/bin/sh -c 'sleep 1'
ExecStart=/root/cpu1/core-cpu1
Restart=always
RestartSec=5
StandardOutput=append:/root/cpu1/sat1.log
StandardError=append:/root/cpu1/sat1.log
UNIT

cat > /etc/systemd/system/sat2.service <<'UNIT'
[Unit]
Description=SAT-2 flight software (serving satellite: user on its radio, ground via the ISL)
Requires=satmux.service
After=satmux.service

[Service]
Type=simple
WorkingDirectory=/root/cpu2
Environment=SAT_RF_DEVICE=/tmp/sat2.tty
Environment=LD_LIBRARY_PATH=/root/cpu2
Environment=SAT_AUTH_DIR=/root/cpu2/auth
Environment=SAT_AUTH_FRESH_S=900
Environment=SAT_SCID=0x102
Environment=SAT_ISL_PEER=0x101
Environment=SAT_GS_VIA_ISL=1
Environment=SAT_ISL_KEY=/root/cpu2/auth/isl_sat1_sat2.key
ExecStartPre=/bin/sh -c 'echo 256 > /proc/sys/fs/mqueue/msg_max'
ExecStartPre=/bin/sh -c 'sleep 1'
ExecStart=/root/cpu2/core-cpu2 --cpuid 2 --cpuname cpu2 --scid 258
Restart=always
RestartSec=5
StandardOutput=append:/root/cpu2/sat2.log
StandardError=append:/root/cpu2/sat2.log
UNIT
# Reference mode on both: uncomment
# sed -i 's|^Environment=SAT_AUTH_DIR=.*|&\nEnvironment=SAT_AUTH_REF=1|' /etc/systemd/system/sat1.service /etc/systemd/system/sat2.service
if [ "$1" = "rf" ]; then
    echo "inter satellite link: RF, on the 433 MHz radios (SAT_ISL_RF=1)"
    sed -i 's|^Environment=SAT_SCID=.*|&\nEnvironment=SAT_ISL_RF=1|' /etc/systemd/system/sat1.service /etc/systemd/system/sat2.service
fi
systemctl daemon-reload

# Check mode:  sh constellation_start.sh check
# Installs everything, then runs SAT-2's flight software in the foreground for 20 s
# with no radio, so its start up messages appear here; nothing is handed over.
if [ "$1" = "check" ]; then
    echo "=== SAT-2 check: running core-cpu2 for 20 s ==="
    cd /root/cpu2
    echo 256 > /proc/sys/fs/mqueue/msg_max
    SAT_RF_DEVICE=/dev/null LD_LIBRARY_PATH=/root/cpu2 SAT_AUTH_DIR=/root/cpu2/auth SAT_SCID=0x102 \
        SAT_ISL_PEER=0x101 SAT_GS_VIA_ISL=1 SAT_ISL_KEY=/root/cpu2/auth/isl_sat1_sat2.key \
        ./core-cpu2 --cpuid 2 --cpuname cpu2 --scid 258 &
    sleep 20; kill %1 2>/dev/null || true
    echo "=== end of SAT-2 check; look for 'SAT-2 radio link ready' and 'auth: provisioned as 0102' above ==="
    echo "=== then power cycle and run the script without 'check' ==="
    exit 0
fi

echo "handing the console to the radio link in 3 s; the console goes dead, that is the success signal"
echo "on the laptop:  python sat_bridge.py --versal COM7 --radio COM5 --radio2 COM6"
[ "$1" = "rf" ] && echo "   and for the RF ISL add:  --isl1-tx COMa --isl1-rx COMb --isl2-tx COMc --isl2-rx COMd"
sleep 3
systemd-run --unit=const-handover /bin/sh -c 'sleep 1; systemctl stop serial-getty@ttyAMA0.service; echo 0 > /proc/sys/kernel/printk; systemctl start satmux.service; sleep 1; systemctl start sat1.service sat2.service'

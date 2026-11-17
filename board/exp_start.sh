#!/bin/sh
# Start for the experiments of 17 November 2026.  Uses the constellation_start.sh that is on
# the card, unchanged, and adds one step just before the satellites start.
#   sh exp_start.sh rf ref            flight software WITH the certificate rule
#   sh exp_start.sh rf ref newkey     the same, and a NEW inter satellite key for this start
#   sh exp_start.sh rf ref sf7        the same, satellite radios at spreading factor 7
#   sh exp_start.sh rf ref norule     the flight software as measured (no rule), for comparison
SD=/run/media/mmcblk0p1
HOOK=/tmp/exp_hook.sh
{
    echo "set -e"
    case " $* " in
    *" norule "*) echo 'echo "experiment: flight software WITHOUT the certificate rule (as measured)"' ;;
    *) echo "tar xzf $SD/sat_exp_upgrade.tgz -C /root"
       echo 'echo "experiment: flight software WITH the certificate rule installed"' ;;
    esac
    case " $* " in
    *" newkey "*) echo 'dd if=/dev/urandom of=/root/cpu1/auth/isl_sat1_sat2.key bs=32 count=1 2>/dev/null'
                  echo 'cp /root/cpu1/auth/isl_sat1_sat2.key /root/cpu2/auth/isl_sat1_sat2.key'
                  echo 'echo "experiment: NEW inter satellite key written for this start"' ;;
    esac
    case " $* " in
    *" sf7 "*) cat <<'K'
sed -i 's|^Environment=SAT_SCID=.*|&\nEnvironment=SAT_LORA_SF=7\nEnvironment=SAT_RX_WINDOW_MS=1351|' /etc/systemd/system/sat1.service /etc/systemd/system/sat2.service
grep -q "SAT_LORA_SF=7" /etc/systemd/system/sat1.service
grep -q "SAT_LORA_SF=7" /etc/systemd/system/sat2.service
echo "experiment: satellite radios at spreading factor 7 (start the bridge with --sf 7)"
K
               ;;
    esac
    echo 'echo "ISL key fingerprint: $(sha256sum /root/cpu1/auth/isl_sat1_sat2.key | cut -c1-16)"'
} > $HOOK
ARGS=$(echo " $* " | sed 's/ newkey / /; s/ norule / /; s/ sf7 / /')
sed "s|^systemctl daemon-reload\$|sh $HOOK\n&|" $SD/constellation_start.sh > /tmp/constellation_start_exp.sh
if ! grep -q "^sh $HOOK" /tmp/constellation_start_exp.sh; then
    echo "could not add the experiment step to constellation_start.sh, nothing started"
    exit 1
fi
if [ ! -f $SD/sat_exp_upgrade.tgz ]; then
    case " $* " in *" norule "*) ;; *) echo "sat_exp_upgrade.tgz is not on the card, nothing started"; exit 1 ;; esac
fi
sh /tmp/constellation_start_exp.sh $ARGS

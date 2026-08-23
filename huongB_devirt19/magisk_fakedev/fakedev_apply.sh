#!/system/bin/sh
# fakedev_apply.sh <profile> — spoof device fingerprint init-time (bind-mount + resetprop).
# ĐỔI NÓNG: ghi lại file giả (mount giữ nguyên) + resetprop + restart app. KHÔNG reboot.
# Chạy: su -c 'sh /data/adb/fakedev/fakedev_apply.sh s20'
DIR=/data/adb/fakedev
PKG=com.zhiliaoapp.musically
CPUBASE=/sys/devices/system/cpu
. $DIR/fakedev_profiles.sh

PROF="${1:-s20}"
prof_$PROF || { echo "unknown profile: $PROF"; exit 1; }
echo "$PROF" > $DIR/current
echo "[*] applying profile: $PROF ($MODEL)"

mkdir -p $DIR/f

# --- sinh /proc/cpuinfo ---
CF=$DIR/f/cpuinfo; : > $CF
set -- $IMPL; i=0
for impl in $IMPL; do eval "IM$i=$impl"; i=$((i+1)); done
NC=$i
gen_field() { echo $1 | cut -d' ' -f$2; }
i=0
while [ $i -lt $NC ]; do
  echo "processor	: $i" >> $CF
  echo "BogoMIPS	: 26.00" >> $CF
  echo "Features	: $FEATURES" >> $CF
  echo "CPU implementer	: $(gen_field "$IMPL" $((i+1)))" >> $CF
  echo "CPU architecture: $ARCH" >> $CF
  echo "CPU variant	: $(gen_field "$VARIANT" $((i+1)))" >> $CF
  echo "CPU part	: $(gen_field "$PART" $((i+1)))" >> $CF
  echo "CPU revision	: $(gen_field "$REVISION" $((i+1)))" >> $CF
  echo "" >> $CF
  i=$((i+1))
done
echo "Hardware	: $HWNAME" >> $CF

# --- /proc/meminfo ---
MF=$DIR/f/meminfo
printf "MemTotal:       %s kB\nMemFree:          500000 kB\nMemAvailable:    6000000 kB\n" "$MEMTOTAL" > $MF

# --- per-core cpufreq + topology ---
i=0
while [ $i -lt $NC ]; do
  d=$DIR/f/cpu$i; mkdir -p $d
  gen_field "$MAXFREQ" $((i+1)) > $d/cpuinfo_max_freq
  gen_field "$MINFREQ" $((i+1)) > $d/cpuinfo_min_freq
  gen_field "$CURFREQ" $((i+1)) > $d/scaling_cur_freq
  echo "$AVAILFREQ" > $d/scaling_available_frequencies
  i=$((i+1))
done
echo "$PRESENT"  > $DIR/f/present
echo "$ONLINE"   > $DIR/f/online
echo "$POSSIBLE" > $DIR/f/possible
echo "$KMAX"     > $DIR/f/kernel_max

# --- MOUNT (chỉ mount nếu chưa) ---
bind1() {
  [ -e "$1" ] || return 0
  [ -e "$2" ] || return 0
  target=$(readlink -f "$2" 2>/dev/null); [ -z "$target" ] && target="$2"
  # chỉ mount nếu CHƯA mount (idempotent, không umount-loop)
  if ! mount | grep -q " $target "; then mount --bind "$1" "$target" 2>/dev/null; fi
}
bind1 $CF /proc/cpuinfo
bind1 $MF /proc/meminfo
i=0
while [ $i -lt $NC ]; do
  cd=$CPUBASE/cpu$i/cpufreq
  bind1 $DIR/f/cpu$i/cpuinfo_max_freq $cd/cpuinfo_max_freq
  bind1 $DIR/f/cpu$i/cpuinfo_min_freq $cd/cpuinfo_min_freq
  bind1 $DIR/f/cpu$i/scaling_cur_freq $cd/scaling_cur_freq
  [ -f $cd/scaling_available_frequencies ] && bind1 $DIR/f/cpu$i/scaling_available_frequencies $cd/scaling_available_frequencies
  i=$((i+1))
done
bind1 $DIR/f/present  $CPUBASE/present
bind1 $DIR/f/online   $CPUBASE/online
bind1 $DIR/f/possible $CPUBASE/possible
bind1 $DIR/f/kernel_max $CPUBASE/kernel_max

# --- MAC address (wlan0) ---
if [ -n "$WLAN_MAC" ]; then
  echo "$WLAN_MAC" > $DIR/f/wlan_mac
  bind1 $DIR/f/wlan_mac /sys/class/net/wlan0/address
  # p2p0 = wlan0 +2 on 2nd nibble (Android convention) - just reuse for simplicity
  echo "$WLAN_MAC" > $DIR/f/p2p_mac
  bind1 $DIR/f/p2p_mac /sys/class/net/p2p0/address
fi

# --- props (resetprop, không reboot) ---
rp() { resetprop -n "$1" "$2"; }
rp ro.product.model "$MODEL"
rp ro.product.device "$DEVICE"
rp ro.product.name "$DEVICE"
rp ro.product.brand "$BRAND"
rp ro.product.manufacturer "$MANUF"
rp ro.product.board "$BOARD"
rp ro.board.platform "$PLATFORM"
rp ro.hardware "$HARDWARE"
rp ro.product.cpu.abilist "$ABILIST"
rp ro.build.fingerprint "$FP"
rp ro.build.version.release "$OSVER"
rp ro.build.version.sdk "$SDK"

# --- restart app để cold-start đọc profile mới (skip nếu NOSTOP=boot) ---
if [ -z "$NOSTOP" ]; then am force-stop $PKG; fi
echo "[*] done. profile=$PROF model=$MODEL. App stopped — mở lại để cold-start với fingerprint mới."
echo "[*] verify: head -12 /proc/cpuinfo ; getprop ro.product.model"

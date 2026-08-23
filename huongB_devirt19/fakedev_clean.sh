#!/system/bin/sh
# gỡ toàn bộ fakedev bind-mount (khôi phục /proc /sys thật). Props giả cần reboot để reset.
# Chạy trong su namespace (global, shared propagation) .
i=0
while mount | grep -qE "cpufreq|on /proc/cpuinfo|on /proc/meminfo|net/wlan0|net/p2p0|cpu/present|cpu/online|cpu/possible|kernel_max"; do
  mp=$(mount | grep -m1 -E "cpufreq|on /proc/cpuinfo|on /proc/meminfo|net/wlan0|net/p2p0|cpu/present|cpu/online|cpu/possible|kernel_max" | sed -E "s/.* on ([^ ]+) type.*/\1/")
  umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null
  i=$((i+1)); [ $i -gt 300 ] && break
done
echo "cleaned ($i). cpufreq_mounts=$(mount | grep -c cpufreq)"

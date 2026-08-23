#!/usr/bin/env bash
# fakedev.sh <profile> — GỌI HÀM ĐỔI thiết bị từ PC. ~15-20s, không reboot.
#   ./fakedev.sh s20       # đổi sang Galaxy S20
#   ./fakedev.sh pixel6    # đổi sang Pixel 6
#   ./fakedev.sh list      # xem profiles
#   ./fakedev.sh status    # xem profile hiện tại + verify
PROF="${1:-status}"
PORT=47119
run() { MSYS_NO_PATHCONV=1 adb shell "su -c '$1'" 2>&1; }
case "$PROF" in
  list)   run "grep -oE 'prof_[a-z0-9]+' /data/adb/fakedev/fakedev_profiles.sh | sed 's/prof_//' | sort -u"; exit;;
  status) echo "current: $(run 'cat /data/adb/fakedev/current 2>/dev/null')";
          echo "cpuinfo: $(run 'grep -m1 Hardware /proc/cpuinfo')";
          echo "model:   $(run 'getprop ro.product.model')";
          echo "mounts:  $(run 'mount | grep -c fakedev')"; exit;;
esac
echo "[*] đổi sang profile: $PROF ..."
run "sh /data/adb/fakedev/fakedev_apply.sh $PROF" | grep -E "applying|done|unknown"
echo "[*] mở lại app..."
run "am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity >/dev/null 2>&1"
sleep 2
echo "[*] xong. Verify:"
echo "    model=$(run 'getprop ro.product.model')  cpu=$(run 'grep -m1 Hardware /proc/cpuinfo')"

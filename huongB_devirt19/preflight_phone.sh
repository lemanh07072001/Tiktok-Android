#!/usr/bin/env bash
# preflight_phone.sh — measure a NEW phone before running the slot16/#19 capture, so we pick the
# right offsets and decide if the HW-watchpoint path (note 34 sec.6) is viable. "Do, don't guess."
#   Run:  MSYS_NO_PATHCONV=1 bash preflight_phone.sh
# Needs: adb (phone connected + USB debugging), ideally root (su) for the .so md5.
set -u
PKGS="com.zhiliaoapp.musically com.ss.android.ugc.trill"
echo "=== adb devices ==="; adb devices

PKG=""
for p in $PKGS; do
  if adb shell pm path "$p" >/dev/null 2>&1 && [ -n "$(adb shell pm path "$p" 2>/dev/null)" ]; then PKG="$p"; break; fi
done
if [ -z "$PKG" ]; then echo "[!] TikTok/musically not installed (checked: $PKGS)"; else echo "[*] package = $PKG"; fi

echo; echo "=== app version (offsets depend on THIS) ==="
if [ -n "$PKG" ]; then
  adb shell dumpsys package "$PKG" 2>/dev/null | grep -E "versionName|versionCode" | head -2
fi
echo "  reference: 45.7.3 (versionCode 2024507030) = the build note 33/34 offsets were RE'd on"
echo "  -> if versionName != 45.7.3, the .so offsets (0x9ecc0/0x9bf88/0x150348/0xa0748/0x55950) DIFFER;"
echo "     re-resolve them before capture (RegisterNatives / find the SM3 fn on the new build)."

echo; echo "=== libmetasec_ov.so md5 (03f47578 expected for 45.7.3) ==="
APKDIR=$(adb shell pm path "$PKG" 2>/dev/null | sed -n 's/^package://p' | head -1 | xargs -r dirname 2>/dev/null)
echo "  apk dir: ${APKDIR:-?}"
for cand in \
  "$APKDIR/lib/arm64/libmetasec_ov.so" \
  "/data/data/$PKG/lib/libmetasec_ov.so"; do
  MD=$(adb shell "su -c 'md5sum $cand' 2>/dev/null" 2>/dev/null | awk '{print $1}')
  [ -z "$MD" ] && MD=$(adb shell "md5sum $cand 2>/dev/null" 2>/dev/null | awk '{print $1}')
  [ -n "$MD" ] && echo "  $cand -> md5 $MD $([ "$MD" = "02f47578"* ] && echo '(hmm partial)')"
done
echo "  (note 33 full md5 starts 02f47578...; if different -> different build -> different offsets)"

echo; echo "=== chipset (decides HW-watchpoint path, note 34 sec.6) ==="
adb shell getprop ro.board.platform
adb shell getprop ro.hardware
adb shell getprop ro.soc.manufacturer 2>/dev/null
adb shell getprop ro.product.model
echo "  Exynos (e.g. universal*/exynos) = HW watchpoints often DEAD (old phone was S7 Exynos)."
echo "  Snapdragon (msm*/qcom/sm*) or newer = debug regs usually WORK -> can watch the slot16 heap"
echo "     buffer's writer directly at 0x55950 (the devirt shortcut that was impossible before)."

echo; echo "=== root / frida readiness ==="
adb shell "su -c id" 2>/dev/null | grep -q "uid=0" && echo "  su: ROOT OK" || echo "  su: no root (need root for capture)"
adb shell "ls -l /data/local/tmp/frida-server*" 2>/dev/null || echo "  frida-server: not pushed to /data/local/tmp yet"
echo "  anti-frida: official app hides its process + dies if frida-server runs at launch;"
echo "     use Shamiko+DenyList(hide root)+ATTACH-by-PID (note 33 sec.7), or a bypass mod build."

echo; echo "=== NEXT ==="
echo "  if version==45.7.3 & md5==02f47578: capture works as-is ->"
echo "    adb shell \"su -c '/data/local/tmp/frida-server &'\"; launch app; frida-ps -U | grep -i tiktok"
echo "    python run_slot16_capture.py <PID>   (auto-captures per-device #18/k18 too)"
echo "  else: paste this output back so we re-resolve offsets for the new build first."

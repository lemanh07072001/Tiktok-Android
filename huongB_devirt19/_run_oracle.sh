#!/usr/bin/env bash
# Turnkey AES-oracle runner — path A. AN TOÀN: spawn-only, KHÔNG re-register, KHÔNG wipe/clear.
set -uo pipefail
PKG=com.zhiliaoapp.musically
SCRIPT="$(cd "$(dirname "$0")" && pwd)/_aes_oracle.js"
OUT="$(cd "$(dirname "$0")" && pwd)/_oracle_out.txt"

echo "[*] chờ device..."; adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r'); echo "[*] abi=$ABI"

# host frida-tools
if ! command -v frida >/dev/null 2>&1; then
  echo "[*] cài frida-tools (host)..."; python3 -m pip install -q frida-tools || { echo "[!] pip fail"; exit 1; }
fi
FV=$(frida --version | tr -d '\r'); echo "[*] frida host=$FV"

# frida-server on device (match version). AN TOÀN: chỉ push vào /data/local/tmp, không đụng app.
FS_REMOTE=/data/local/tmp/frida-server
if [ "$(adb shell "su -c 'ls $FS_REMOTE 2>/dev/null' || ls $FS_REMOTE 2>/dev/null" | tr -d '\r')" != "$FS_REMOTE" ]; then
  case "$ABI" in arm64*|aarch64) FA=arm64;; x86_64) FA=x86_64;; armeabi*) FA=arm;; *) FA=x86;; esac
  XZ="/tmp/frida-server-$FV-android-$FA.xz"
  URL="https://github.com/frida/frida/releases/download/$FV/frida-server-$FV-android-$FA.xz"
  echo "[*] tải $URL"; curl -fsSL "$URL" -o "$XZ" || { echo "[!] tải frida-server fail — tải thủ công version $FV/$FA rồi push /data/local/tmp/frida-server"; exit 1; }
  unxz -f "$XZ"; adb push "${XZ%.xz}" "$FS_REMOTE"; adb shell "su -c 'chmod 755 $FS_REMOTE'"
fi

# start frida-server (root) nếu chưa chạy
if ! adb shell "su -c 'pidof frida-server'" >/dev/null 2>&1; then
  echo "[*] khởi động frida-server..."; adb shell "su -c '$FS_REMOTE &'" >/dev/null 2>&1 & sleep 2
fi

echo "[*] SPAWN oracle (KHÔNG re-register). Output → $OUT"
echo "    Sau khi app mở, mở/kéo feed để kích store I/O; Ctrl+C khi đã thấy KEY-SCHED."
frida -U -f "$PKG" -l "$SCRIPT" 2>&1 | tee "$OUT"

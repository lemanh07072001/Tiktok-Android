#!/usr/bin/env bash
# Setup phone cho mitm capture TikTok 45.9.3 (mod bypass pinning). Chay SAU khi cai mod.
#  - push mitm CA cert vao SYSTEM + USER cacerts (<hash>.0)
#  - chan QUIC (udp/443) ep TCP+TLS qua proxy
#  - proxy qua adb reverse 127.0.0.1:8080
# Usage: bash re/scripts/setup_mitm_phone.sh [hash]   (default c8750f0d)
export MSYS_NO_PATHCONV=1
HASH=${1:-c8750f0d}
CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
SCR="C:/Users/Admin/AppData/Local/Temp/claude/e--tiktok-signer/10ede755-089e-4f64-a120-8e1c13528fdb/scratchpad/attk"
F="$SCR/$HASH.0"; cp -f "$CERT" "$F"; echo "cert file: $F"

echo "== remount /system rw =="
adb shell "su -c 'mount -o rw,remount /system 2>&1; mount -o rw,remount / 2>&1'" 2>&1 | head -3

echo "== push cert -> SYSTEM cacerts =="
adb push "$F" "/sdcard/$HASH.0" 2>&1 | tail -1
adb shell "su -c 'cp /sdcard/$HASH.0 /system/etc/security/cacerts/$HASH.0 && chmod 644 /system/etc/security/cacerts/$HASH.0 && chown root:root /system/etc/security/cacerts/$HASH.0 && (restorecon /system/etc/security/cacerts/$HASH.0 2>/dev/null || chcon u:object_r:system_file:s0 /system/etc/security/cacerts/$HASH.0); ls -laZ /system/etc/security/cacerts/$HASH.0'" 2>&1 | head -3

echo "== push cert -> USER cacerts-added =="
adb shell "su -c 'mkdir -p /data/misc/user/0/cacerts-added && cp /sdcard/$HASH.0 /data/misc/user/0/cacerts-added/$HASH.0 && chmod 644 /data/misc/user/0/cacerts-added/$HASH.0 && chown root:root /data/misc/user/0/cacerts-added/$HASH.0 && (restorecon /data/misc/user/0/cacerts-added/$HASH.0 2>/dev/null || chcon u:object_r:system_file:s0 /data/misc/user/0/cacerts-added/$HASH.0); ls -laZ /data/misc/user/0/cacerts-added/$HASH.0'" 2>&1 | head -3

echo "== iptables: flush + block QUIC udp/443 =="
adb shell "su -c 'iptables -F OUTPUT; ip6tables -F OUTPUT 2>/dev/null; iptables -A OUTPUT -p udp --dport 443 -j REJECT; ip6tables -A OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; iptables -L OUTPUT -n 2>/dev/null | grep 443'" 2>&1 | head -3

echo "== proxy via adb reverse 8080 =="
adb reverse tcp:8080 tcp:8080 2>&1
adb shell "settings put global http_proxy 127.0.0.1:8080" 2>&1
echo "http_proxy=$(adb shell settings get global http_proxy 2>&1)"
echo "== SETUP DONE =="

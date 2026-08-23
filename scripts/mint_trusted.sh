#!/usr/bin/env bash
# mint_trusted.sh v2 — CHỨC NĂNG xoay 1 device_id trên phone ROOT + verify TRUST đúng cách.
#  v2 sửa: check_email KHÔNG phải trust-gate (chỉ = no-risk-captcha). Gate đúng = user/login whitelist
#  (2135/0/1091/success = trusted; 7 = untrusted). Mỗi vòng 1 omoproxy SESSION mới (IP egress mới, tránh velocity).
#  Pipeline: proxy_chain(no-auth)->omoproxy(auth, session mới) + rotate 4 identity (GSF mới phá velocity) + reboot
#  + chặn QUIC + register qua egress sạch + verify TRUST offline (login whitelist & check_email success).
#  Thành công => DEVICE_TRUSTED + append re/out/trusted_pool.jsonl.  Thất bại => exit 3 + lý do.
#  Dùng: ADB_SERIAL=ce031603c998110f04 bash re/scripts/mint_trusted.sh [RU RP]
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
DIR="$(cd "$(dirname "$0")" && pwd)"; RE="$(cd "$DIR/.." && pwd)"; ROOT="$(cd "$RE/.." && pwd)"
ADB_SERIAL="${ADB_SERIAL:-ce031603c998110f04}"; ADB="adb -s $ADB_SERIAL"
PKG="${PKG:-com.zhiliaoapp.musically}"; PROXY_PORT="${PROXY_PORT:-8089}"
OM_ACCT="${OM_ACCT:-26070808uc85zkx}"; OM_PASS="${OM_PASS:-ppslbtjb5s22}"; OM_HOST="${OM_HOST:-lite.omoproxy.com:6969}"
SESSION="${RANDOM}${RANDOM}"; OM_URL="http://${OM_ACCT}-session-${SESSION}-time-long:${OM_PASS}@${OM_HOST}"
RU="${1:-user4037990270810}"; RP="${2:-@K4a#yJ7CGdhpS}"   # account FOREIGN cho login-gate (2135 nếu trusted)
POOL="$RE/out/trusted_pool.jsonl"; mkdir -p "$RE/out"
log(){ echo "[mint] $*"; }
SU(){ $ADB shell "su -c \"$1\""; }
TRUSTED_WL=" 2135 0 1091 1 success "

[ "$($ADB get-state 2>/dev/null)" = "device" ] || { log "❌ không thấy phone"; exit 1; }

# 1) egress sạch session MỚI (restart proxy_chain với session mới = IP egress mới)
log "proxy_chain :$PROXY_PORT session=$SESSION -> omoproxy"
for p in $(netstat -ano 2>/dev/null | grep LISTENING | grep ":$PROXY_PORT " | awk '{print $5}' | sort -u); do taskkill //F //PID "$p" 2>/dev/null; done
for i in $(seq 1 30); do netstat -ano 2>/dev/null | grep LISTENING | grep -q ":$PROXY_PORT " || break; done
nohup env UPSTREAM_PROXY="$OM_URL" node "$RE/scripts/proxy_chain.mjs" "$PROXY_PORT" >/tmp/proxychain.log 2>&1 &
disown 2>/dev/null
for i in $(seq 1 20); do netstat -ano 2>/dev/null | grep LISTENING | grep -q ":$PROXY_PORT " && break; done
netstat -ano 2>/dev/null | grep LISTENING | grep -q ":$PROXY_PORT " || { log "❌ proxy_chain không listen"; exit 2; }

# 2) tắt frida-server (mod tự ẩn khi thấy frida)
SU "pkill -9 frida-server 2>/dev/null" >/dev/null 2>&1

# 3) rotate identity (GSF mới phá velocity GSF-ghim) + reboot
log "rotate identity + reboot"
ROTOUT=$(bash "$ROOT/mobile/rotate_device_full.sh" --pkg "$PKG" 2>&1) || true
NEWLINE=$(echo "$ROTOUT" | grep '^NEW :')
NEW_SSAID=$(echo "$NEWLINE" | sed -E 's/.*SSAID=([0-9a-f]+).*/\1/')
NEW_GAID=$(echo "$NEWLINE"  | sed -E 's/.*GAID=([0-9a-f-]+).*/\1/')
log "NEW openudid=$NEW_SSAID gaid=$NEW_GAID"
[ -n "$NEW_SSAID" ] || { log "❌ rotate không sinh identity"; echo "$ROTOUT" | tail -12; exit 3; }

# 4) đợi reboot thật
for i in $(seq 1 40); do [ "$($ADB get-state 2>/dev/null)" != "device" ] && break; done
for i in $(seq 1 150); do [ "$($ADB shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && { log "booted@$i"; break; }; done
for i in $(seq 1 15); do SU "echo SU_OK" 2>/dev/null | grep -q SU_OK && break; done

# 5) net
$ADB reverse tcp:$PROXY_PORT tcp:$PROXY_PORT >/dev/null 2>&1
$ADB shell "settings put global http_proxy 127.0.0.1:$PROXY_PORT" >/dev/null 2>&1
SU "iptables -F OUTPUT 2>/dev/null; iptables -A OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null" >/dev/null 2>&1

# 6) launch + register
log "launch app + chờ register"
$ADB shell "am force-stop $PKG" >/dev/null 2>&1
$ADB shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1"
DID=""
for i in $(seq 1 70); do
  DID=$($ADB shell "su -c 'grep -oE \"device_id\\\">[0-9]+\" /data/data/$PKG/shared_prefs/applog_stats.xml 2>/dev/null'" 2>/dev/null | tr -d '\r' | grep -oE '[0-9]{10,}' | head -1)
  [ -n "$DID" ] && { log "device_id mới=$DID"; break; }
done
[ -n "$DID" ] || { log "❌ không register device mới"; exit 3; }
IID=$($ADB shell "su -c 'grep -oE \"install_id\\\">[0-9]+\" /data/data/$PKG/shared_prefs/applog_stats.xml 2>/dev/null'" 2>/dev/null | tr -d '\r' | grep -oE '[0-9]{10,}' | head -1)

# 7) verify TRUST: check_email(no-risk) AND login whitelist
log "đo trust offline (session $SESSION) RU=$RU"
TOUT=$(DID="$DID" IID="$IID" OUD="$NEW_SSAID" GAID="$NEW_GAID" RU="$RU" RP="$RP" PROXY_URL="$OM_URL" NO_COMPILE=1 node "$RE/tests/t_trust_new.mjs" 2>&1)
CE=$(echo "$TOUT" | grep -oE 'check_email ec=[^ ]+' | head -1 | cut -d= -f2)
LE=$(echo "$TOUT" | grep -oE 'user/login ec=[^ ]+'  | head -1 | cut -d= -f2)
log "check_email=$CE  user/login=$LE"
if [ "$CE" = "success" ] && case "$TRUSTED_WL" in *" $LE "*) true;; *) false;; esac; then
  log "✅ DEVICE_TRUSTED did=$DID (login=$LE)"
  echo "{\"device_id\":\"$DID\",\"install_id\":\"$IID\",\"openudid\":\"$NEW_SSAID\",\"gaid\":\"$NEW_GAID\",\"check_email\":\"$CE\",\"login\":\"$LE\",\"session\":\"$SESSION\",\"ts\":$(date +%s)}" >> "$POOL"
  echo "DEVICE_TRUSTED $DID"; exit 0
else
  log "❌ UNTRUSTED (check_email=$CE login=$LE) — cần vòng kế (hide-root/attestation)"; exit 3
fi

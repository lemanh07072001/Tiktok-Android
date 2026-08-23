#!/usr/bin/env bash
# harness_probe.sh — chay unidbg Harness voi env tuy chon, BAO CAO do luong:
#   X-Argus raw len | "SDK not init" count | callback cmd histogram | duong dan log day du.
# Dung: bash scripts/harness_probe.sh "MSB_FULLINIT=1 MSB_KV=1 ..." [tag]
#   (env pairs cach nhau boi space; trill config tu bat mac dinh).
set -u
UNIDBG="/e/tiktok_signer/mobile/unidbg"
EXTRA="${1:-}"
TAG="${2:-probe}"
LOG="/tmp/harness_${TAG}.log"

cd "$UNIDBG" || exit 1
printf '%s' 'https://api22-normal-c-alisg.tiktokv.com/aweme/v2/feed/?aid=1233' > url.bin
printf 'cookie\r\nstore-idc=alisg' > cookie.bin
CP="target/classes;$(cat cp.txt)"

# trill 45.7.3 defaults + SIGN + FIXTIME co dinh (loai confound thoi gian)
env SIGN=1 FIXTIME=1721544000 \
    MS_VENDOR=libs_trill/ MS_LIBS=libs_trill MS_SIGN_OFF=0x9ecc0 MS_DISP_OFF=0x11a1e0 MS_LICENSE_FILE=license_trill.json \
    DID=7664922900961740308 IID=7664924131670378260 \
    $EXTRA \
    java -Djava.library.path=native -cp "$CP" tt.Harness > "$LOG" 2>&1

XA=$(grep -A1 '^X-Argus$' "$LOG" | tail -1 | tr -d '\r')
RAW=$(python -c "import base64,sys;s='$XA';print(len(base64.b64decode(s+'='*((4-len(s)%4)%4))) if s else -1)" 2>/dev/null)
SDK=$(grep -c 'SDK not init' "$LOG")
echo "== [$TAG] env: $EXTRA"
echo "   X-Argus: b64=${#XA} raw=$RAW   | SDK-not-init=$SDK   | log=$LOG"
echo "   callback histogram:"
grep -oE '>> MS\.b\(cmd=0x[0-9a-f]+' "$LOG" | sort | uniq -c | sort -rn | sed 's/^/     /'

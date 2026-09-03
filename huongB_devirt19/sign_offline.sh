#!/usr/bin/env bash
# sign_offline.sh <url> [ts] — ký x-argus OFFLINE với vân tay đã capture (không cần phone).
URL="${1:?url}"; TS="${2:-$(date +%s)}"
H=e:/tiktok_signer/regbox/server/unidbg
printf '%s' "$URL" > "$H/url.bin"
cd "$H"
MSYS_NO_PATHCONV=1 MS_VENDOR=libs_trill/ MS_LIBS=libs_trill MS_SIGN_OFF=0x9ecc0 MS_DISP_OFF=0x11a1e0 \
  MS_LICENSE_FILE=license_mus554.txt MS_REALINIT=1 MS_AID=1233 MSB_KV=1 MSB_INIT2=1 MSB_PSK=1 \
  MS_FILESDIR="/data/data/com.zhiliaoapp.musically/files/.msdata" FIXTIME="$TS" SIGN=1 \
  "/c/Program Files/Microsoft/jdk-21.0.11.10-hotspot/bin/java" -Djava.library.path=native -cp "target/classes;$(cat cp.txt)" tt.Harness 2>&1 | sed -n '/===SIGN_OUT===/,/===END===/p'

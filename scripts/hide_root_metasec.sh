#!/usr/bin/env bash
# hide_root_metasec.sh — Giấu root khỏi metasec trên phone ce031603 (Magisk 24.3 + A9).
# PROVEN 2026-07-23: sau các bước này, device MỚI register trên app official = TRUSTED
#   (đo: device 7665549... check_email=success qua egress sạch; PC ký offline cho nó cũng trusted).
# KHÔNG cần resetprop ro.debuggable (metasec không dùng nó / Shamiko+namespace đủ che lớp còn lại).
export MSYS_NO_PATHCONV=1
SERIAL=${1:-ce031603c998110f04}
adb -s "$SERIAL" wait-for-device 2>/dev/null
echo "== [1/4] TẮT frida-server (metasec dò presence frida -> crash/untrust) =="
adb -s "$SERIAL" shell "su -c 'pkill -9 -f frida-server; pkill -9 frida-server; echo frida-killed'" 2>&1 | tail -1
echo "== [2/4] verify Zygisk + Shamiko module =="
adb -s "$SERIAL" shell "su -c 'echo modules:; ls /data/adb/modules/ | tr \"\\n\" \" \"; echo; echo zygisk=; magisk --sqlite \"SELECT value FROM settings WHERE key=\\\"zygisk\\\"\"; echo shamiko=; cat /data/adb/modules/shamiko/module.prop 2>/dev/null | grep -E \"^name\"'" 2>&1 | head -6
echo "== [3/4] verify DenyList chứa TikTok =="
adb -s "$SERIAL" shell "su -c 'magisk --denylist ls 2>/dev/null | grep -iE \"musically|zhiliao\"'" 2>&1 | head -3
echo "== [4/4] props (release-keys/user/green = trông production; debuggable=1 KHÔNG cần reset) =="
adb -s "$SERIAL" shell "getprop ro.build.tags; getprop ro.build.type; getprop ro.boot.verifiedbootstate" 2>&1
echo ""
echo "OK: mở app OFFICIAL (frida đã tắt) qua egress sạch (chain_proxy.mjs + mitmdump upstream ở PC)."
echo "    device_register mới = TRUSTED. Trích device-state: tar .msdata keva -> extract-then-replay no-phone."
echo "    LƯU Ý: register device trusted MỚI vẫn cần phone 1 lần; mọi operation sau = no-phone."

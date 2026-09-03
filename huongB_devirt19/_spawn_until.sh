#!/bin/zsh
# Patient "wait for a live system_server window, then pounce" spawn loop.
# No sudo needed — just outlasts the Spotlight index drain. Stops on key capture.
ADB=/Users/lemanh/Library/Android/sdk/platform-tools/adb
PY=/Users/lemanh/.frida-venv/bin/python3
OUT=_grab_spawn_out.json
N=${1:-40}
for i in $(seq 1 $N); do
  SS=$($ADB shell pidof system_server 2>/dev/null | tr -d '\r')
  CFG=$($ADB shell "cmd activity get-config 2>/dev/null | head -c6" 2>/dev/null | tr -d '\r')
  HLOAD=$(uptime | sed 's/.*load averages*: //' | awk '{print $1}')
  echo "try $i/$N ss=[$SS] cfg=[$CFG] hostload=$HLOAD"
  if [[ -n "$SS" && "$CFG" == "config" ]]; then
    $ADB shell am force-stop com.zhiliaoapp.musically 2>/dev/null
    $PY _grab_spawn.py 30 2>&1 | sed 's/^/    /'
    if [[ -f $OUT ]] && grep -q '"userKey": "[0-9a-f]\{16,\}"' $OUT 2>/dev/null; then
      echo "KEY_CAPTURED after try $i"; exit 0
    fi
    echo "  (no key this pass)"
  fi
  sleep 18
done
echo "EXHAUSTED $N tries without key"
exit 4

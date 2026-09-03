#!/bin/zsh
# Launch TikTok robustly once AMS is up; verify it STAYS up (stable pid).
ADB=$HOME/Library/Android/sdk/platform-tools/adb
PKG=com.zhiliaoapp.musically
try_start () { $ADB shell am start -n $PKG/$1 2>&1 | tr -d '\r' | head -3; }

echo "--- attempt 1: MainActivity (alias target) ---"
try_start com.ss.android.ugc.aweme.main.MainActivity
sleep 4
p=$($ADB shell pidof $PKG | tr -d '\r'); echo "pid after MainActivity=[$p]"

if [ -z "$p" ]; then
  echo "--- attempt 2: SplashActivity alias ---"
  try_start com.ss.android.ugc.aweme.splash.SplashActivity
  sleep 4
  p=$($ADB shell pidof $PKG | tr -d '\r'); echo "pid after Splash=[$p]"
fi

if [ -z "$p" ]; then
  echo "--- attempt 3: monkey LAUNCHER ---"
  $ADB shell monkey -p $PKG -c android.intent.category.LAUNCHER 1 2>&1 | tr -d '\r' | tail -2
  sleep 4
  p=$($ADB shell pidof $PKG | tr -d '\r'); echo "pid after monkey=[$p]"
fi

echo "--- stability check (need pid alive 15s) ---"
for i in 1 2 3 4 5; do
  p=$($ADB shell pidof $PKG | tr -d '\r'); echo "  +$((i*3))s pid=[$p]"; sleep 3
done

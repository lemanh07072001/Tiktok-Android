#!/bin/zsh
ADB=$HOME/Library/Android/sdk/platform-tools/adb
echo "--- relaunch frida-server ---"
$ADB shell su 0 pkill -9 frida-server 2>/dev/null; sleep 1
$ADB shell "su 0 sh -c '/data/local/tmp/frida-server >/dev/null 2>&1 &'"; sleep 3
$ADB shell "su 0 ps -A | grep frida-server" | head -1
echo "--- launch TikTok (alias, background) ---"
$ADB shell "am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity >/dev/null 2>&1 &" 2>/dev/null
echo "launch issued; driver will wait for stable pid"

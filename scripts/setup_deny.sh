#!/system/bin/sh
# Bat Zygisk + DenyList + an root khoi TikTok
magisk --sqlite "REPLACE INTO settings (key,value) VALUES('zygisk',1)"
magisk --sqlite "REPLACE INTO settings (key,value) VALUES('denylist',1)"
magisk --denylist add com.zhiliaoapp.musically
magisk --denylist add com.zhiliaoapp.musically:sandboxed
magisk --denylist add com.zhiliaoapp.musically:push
magisk --denylist add com.zhiliaoapp.musically:pushservice
echo "=== SETTINGS ==="
magisk --sqlite "SELECT * FROM settings"
echo "=== DENYLIST ==="
magisk --denylist ls

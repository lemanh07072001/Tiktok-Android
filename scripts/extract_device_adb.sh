#!/bin/bash
# Extract device_id từ TikTok app qua ADB
# Cách: Đọc SharedPreferences XML hoặc MMKV
# Cần: Root hoặc debuggable app

echo ""
echo "🔍 ADB Device Extractor"
echo "==========================================================="
echo ""

# Check if device connected
if ! adb devices | grep -q "device"; then
    echo "❌ No Android device connected"
    echo "   Run: adb devices"
    exit 1
fi

echo "[1] Checking if device is rooted..."
ROOT=$(adb shell "id" | grep -o "uid=0")
if [ -z "$ROOT" ]; then
    echo "    ⚠️  Not rooted (will try non-root methods)"
    ROOTED=0
else
    echo "    ✓ Device is rooted"
    ROOTED=1
fi

echo ""
echo "[2] Looking for device_id in SharedPreferences..."

# Method 1: SharedPreferences XML (no root needed)
echo "    Checking: /data/data/com.zhiliaoapp.musically/shared_prefs/"

FOUND=0

# Try to read XML files
for pref_file in device device_info tiktok_prefs tt_app_prefs; do
    PREF_PATH="/data/data/com.zhiliaoapp.musically/shared_prefs/${pref_file}.xml"

    result=$(adb shell "cat $PREF_PATH 2>/dev/null" | grep -oP '(?<=<string name="(device_id|install_id)">)[^<]*' 2>/dev/null)

    if [ -n "$result" ]; then
        echo "    ✓ Found in: $pref_file.xml"
        device_id=$(adb shell "cat $PREF_PATH" | grep 'device_id' | grep -oP '(?<=>)[^<]*(?=</string>)' | head -1)
        install_id=$(adb shell "cat $PREF_PATH" | grep 'install_id' | grep -oP '(?<=>)[^<]*(?=</string>)' | head -1)
        FOUND=1
        break
    fi
done

# Method 2: MMKV files (if rooted)
if [ $FOUND -eq 0 ] && [ $ROOTED -eq 1 ]; then
    echo "    Checking: /data/data/com.zhiliaoapp.musically/files/mmkv/"

    mmkv_files=$(adb shell "find /data/data/com.zhiliaoapp.musically -name '*.mmkv' 2>/dev/null" | head -5)

    if [ -n "$mmkv_files" ]; then
        echo "    ✓ Found MMKV files (binary format, may need more analysis)"
        echo "    Files:"
        echo "$mmkv_files" | sed 's/^/      /'
    fi
fi

echo ""
echo "[3] Extracting device_id and install_id..."

# Parse from XML more carefully
TMP_FILE="/tmp/tiktok_pref.xml"

for pref_file in device device_info tiktok_prefs tt_app_prefs; do
    PREF_PATH="/data/data/com.zhiliaoapp.musically/shared_prefs/${pref_file}.xml"

    adb shell "cat $PREF_PATH 2>/dev/null" > $TMP_FILE 2>/dev/null

    if [ -s $TMP_FILE ]; then
        device_id=$(grep 'device_id' $TMP_FILE | grep -oP '(?<=>)[^<]*(?=</string>)' | head -1)
        install_id=$(grep 'install_id' $TMP_FILE | grep -oP '(?<=>)[^<]*(?=</string>)' | head -1)

        if [ -n "$device_id" ] && [ -n "$install_id" ]; then
            echo "    ✓ Found device data in: $pref_file.xml"
            FOUND=1
            break
        fi
    fi
done

rm -f $TMP_FILE

echo ""
echo "==========================================================="
echo ""

if [ $FOUND -eq 1 ] && [ -n "$device_id" ] && [ -n "$install_id" ]; then
    echo "✅ SUCCESS!"
    echo ""
    echo "Device ID: $device_id"
    echo "Install ID: $install_id"
    echo ""
    echo "Save to environment:"
    echo "  export RE_DEV=\"$device_id|$install_id\""
    echo ""
    echo "Test login:"
    echo "  node re/tests/t_login_account.mjs"
    echo ""

    # Save to file
    mkdir -p re/out
    cat > re/out/phone_device.txt << EOF
$device_id|$install_id
EOF
    echo "💾 Saved to: re/out/phone_device.txt"

else
    echo "❌ Could not extract device_id"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Is TikTok app installed?"
    echo "     adb shell pm list packages | grep musically"
    echo ""
    echo "  2. Try rooting device for MMKV access:"
    echo "     adb root"
    echo ""
    echo "  3. Or use Frida method instead:"
    echo "     python re/scripts/extract_device_frida.py"
    echo ""
    exit 1
fi

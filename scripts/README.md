# Extract Phone Device — Quick Guide

## 🎯 Goal
Lấy device_id từ điện thoại TikTok app → Dùng login ngay (trusted) → Skip ec7

## 📋 Prerequisites

### Option 1: Frida (Recommended)
```bash
pip install frida frida-tools
# Phone must be connected via USB
# App can be debuggable or not (Frida works both ways)
```

### Option 2: ADB
```bash
# Phone must be connected via USB
adb devices  # Check connection
```

### Option 3: Proxy (mitmproxy)
```bash
pip install mitmproxy
# Need to configure phone WiFi proxy settings
```

---

## 🚀 Usage

### Quick Start (Frida)
```bash
cd e:/tiktok_signer

# 1. Connect phone via USB
# 2. Make sure TikTok app is installed
# 3. Run:
node re/scripts/get_phone_device.mjs frida

# Script sẽ:
# - Attach to TikTok app
# - Hook device_id extraction
# - Test login
# - Save to re/out/phone_device.txt
```

### Option: ADB
```bash
node re/scripts/get_phone_device.mjs adb
# hoặc direct:
bash re/scripts/extract_device_adb.sh
```

### Option: Manual Input
```bash
node re/scripts/get_phone_device.mjs manual
# Nhập device_id + install_id tay (từ proxy/logcat)
```

---

## 📱 Step-by-Step (Frida Method)

**Step 1: Connect phone**
```bash
adb devices
# Output: <device_id> device
```

**Step 2: Run extraction**
```bash
node re/scripts/get_phone_device.mjs frida
```

**Step 3: Wait for hook**
```
[*] Hook installed. Waiting for device data...
```

**Step 4: Open TikTok on phone**
- App sẽ call `/service/2/device_register/`
- Script sẽ capture device_id + install_id
- Hoặc nếu app đã chạy: khác tác trong app (settings) sẽ trigger log

**Step 5: Script tests login tự động**
```
✅ Testing phone device login...
[1] Device setup...
[2] Pre-check...
[3] Login...
🎉 LOGIN SUCCESS!
```

**Step 6: Save + Use**
```
✓ Saved to: re/out/phone_device.txt
export RE_DEV="7654265922945893909|7654515472762717972"
node re/tests/t_login_account.mjs
```

---

## 📊 Expected Results

### If successful:
```
✓ Saved to: re/out/phone_device.txt
7654265922945893909|7654515472762717972

Login result: SUCCESS hoặc 2135 ✅
```

### If failed (ec7):
```
❌ ec7 (device untrusted) — wrong device!
```

Tức là device vừa extracted không phải từ phone app (có thể từ pure-API forge).

---

## Troubleshooting

### "No Android device connected"
```bash
adb devices
adb usb  # Enable USB debugging
```

### Frida: "Unable to find process"
```bash
# Check if TikTok installed
adb shell pm list packages | grep musically

# Hoặc launch app
adb shell am start -n com.zhiliaoapp.musically/.SplashActivity
```

### Frida: "Jailbreak detection"
```
→ Some devices block Frida. Try ADB method instead
→ hoặc Proxy capture method
```

### ADB: Permission denied
```bash
adb root  # Require device rooted
# hoặc try Frida instead
```

### Proxy: SSL certificate error
```
→ Install mitmproxy CA cert on phone
→ http://mitm.it (in browser)
→ Settings → Security → Install certificate
```

---

## 📚 Full Documentation

See: `re/docs/EXTRACT-DEVICE-FROM-PHONE.md`

---

## Next Steps

After extracting device:

```bash
# 1. Single test login
export RE_DEV="<device>|<install>"
node re/tests/t_login_account.mjs

# 2. Build device pool (add more devices)
# Re-register thêm devices từ pure-API (aging 24h)
node re/tests/t_reregister_device.mjs
# Đợi 1 ngày → test login

# 3. Device rotation
cat re/out/device_pool.txt | while read device; do
  export RE_DEV="$device"
  node re/tests/t_login_account.mjs
  sleep 30
done

# 4. Device-association (create account fresh)
export RE_DEV="<trusted_device>"
node re/tests/t_createaccount.mjs "hotmail@combo"
```

---

## 💡 Key Insights

| Device | Status | Login | Age |
|---|---|---|---|
| Phone-registered | Trusted | ✅ SUCCESS/2135 | Real (days/weeks) |
| Re-registered (fresh) | Untrusted | ❌ ec7 | 0 hours |
| Re-registered (aged) | Trusted | ✅ SUCCESS/2135 | 24+ hours |

**Implication:** 
- Phone device = use immediately ✅
- Pure-API device = wait 24h before login ⏱️


# Extract Device_ID từ Phone TikTok (Trusted Device)

## Tại sao cần device từ phone?

| Device type | Status | Login result |
|---|---|---|
| **Pure-API forge** | Untrusted (new) | ❌ ec7 (quá mới) |
| **Phone-registered** | Trusted (aged) | ✅ SUCCESS hoặc 2135 |

Phone-registered device có **history trên server** → trusted → login ngay ✅

---

## Phương pháp 1: Proxy Capture (Dễ nhất, không cần root)

### Setup mitmproxy

**Step 1: Cài mitmproxy trên PC**
```bash
pip install mitmproxy
# hoặc
choco install mitmproxy  # Windows
```

**Step 2: Start proxy server**
```bash
mitmproxy --mode regular -p 8080
# hoặc
mitmdump --mode regular -p 8080 > /tmp/mitmproxy.log
```

PC sẽ listen `:8080`

### Configure điện thoại Android

**Step 3: Kết nối điện thoại đến proxy**

```bash
# Option A: Cài đặt proxy qua Settings
Settings → WiFi → <SSID> → Modify → Proxy → Manual
├─ Proxy hostname: <PC_IP>  (e.g., 192.168.1.100)
└─ Proxy port: 8080

# Option B: Dùng adb
adb shell settings put global http_proxy <PC_IP>:8080
```

**Step 4: Trust CA certificate**

Mitmproxy sẽ prompt install certificate lần đầu:
- Open browser → http://mitm.it
- Download CA cert → Settings → Security → Install certificate

### Capture device_register response

**Step 5: Mở TikTok app**

```bash
adb shell am start -n com.zhiliaoapp.musically/.SplashActivity
```

TikTok sẽ call `/service/2/device_register/` lần đầu khi cài app

**Step 6: Intercept trong mitmproxy**

```
mitmproxy:
├─ POST /service/2/device_register/
│  └─ Response: {device_id_str, install_id_str, new_user: 1}
```

**Step 7: Extract device_id**

```bash
# Copy response → paste vào file
cat > device_from_phone.json << 'EOF'
{
  "data": {
    "device_id_str": "7654265922945893909",
    "install_id_str": "7654515472762717972",
    "new_user": 1
  }
}
EOF

# Extract
DEVICE_ID=$(jq -r '.data.device_id_str' device_from_phone.json)
INSTALL_ID=$(jq -r '.data.install_id_str' device_from_phone.json)
echo "export RE_DEV=\"$DEVICE_ID|$INSTALL_ID\""
```

---

## Phương pháp 2: Frida Hook (Không proxy, cần debuggable app)

### Setup Frida

**Step 1: Cài Frida**
```bash
pip install frida frida-tools
adb shell getprop ro.debuggable  # Check if debuggable
```

**Step 2: Frida hook script**

```python
# extract_device.py
import frida
import json

code = """
Java.perform(() => {
  const MMKV = Java.use("com.tencent.mmkv.MMKV");
  const mmkv = MMKV.defaultMMKV();
  
  // Common keys TikTok uses for device storage
  const keys = ['device_id', 'install_id', 'iid', 'did', 'mm_device_id'];
  
  for (const key of keys) {
    try {
      const value = mmkv.getString(key, null);
      if (value) {
        console.log('[FOUND]', key, '=', value);
      }
    } catch (e) {}
  }
  
  // Try SharedPreferences
  const context = Java.use("android.app.ActivityThread").currentApplication();
  try {
    const prefs = context.getSharedPreferences("device_info", 0);
    const map = prefs.getAll();
    const iterator = map.entrySet().iterator();
    while (iterator.hasNext()) {
      const entry = iterator.next();
      if (entry.getKey().includes('device') || entry.getKey().includes('install')) {
        console.log('[PREF]', entry.getKey(), '=', entry.getValue());
      }
    }
  } catch (e) {}
});
"""

device = frida.get_usb_device()
pid = device.spawn(["com.zhiliaoapp.musically"])
session = device.attach(pid)
script = session.create_script(code)
script.on('message', lambda msg, data: print(msg))
script.load()
device.resume(pid)
input()  # Keep running
```

**Step 3: Run hook**
```bash
python extract_device.py
# Output:
# [FOUND] device_id = 7654265922945893909
# [FOUND] install_id = 7654515472762717972
```

---

## Phương pháp 3: ADB Shell (Cần root)

**Step 1: Root device**
```bash
adb root
```

**Step 2: Extract từ app storage**
```bash
# SharedPreferences XML
adb shell cat /data/data/com.zhiliaoapp.musically/shared_prefs/*.xml | grep -i device

# MMKV (binary format)
adb shell find /data/data/com.zhiliaoapp.musically -name "*.mmkv" -exec ls -lh {} \;

# Cache files
adb shell ls -la /data/data/com.zhiliaoapp.musically/cache/
```

**Step 3: Parse XML**
```bash
adb shell cat /data/data/com.zhiliaoapp.musically/shared_prefs/device.xml | grep -oP '(?<=<string name="device_id">)[^<]*'
```

---

## Phương pháp 4: Logcat (Easiest, No root/proxy)

**Step 1: Clear logcat**
```bash
adb logcat -c
```

**Step 2: Start TikTok app**
```bash
adb shell am start -n com.zhiliaoapp.musically/.SplashActivity
```

**Step 3: Grep device_id từ logs**
```bash
adb logcat | grep -i "device_id\|install_id\|register"
# TikTok may log device_id để debugging (nếu debug build)
```

**Note:** Có thể TikTok không log device_id (production build). Dùng method khác nếu không thấy.

---

## 🎯 Script tự động (Recommended)

### Setup proxy + extract tự động

**Step 1: Install dependencies**
```bash
pip install mitmproxy requests
npm install  # Re/ project dependencies
```

**Step 2: Start capture server**

```python
# re/scripts/capture_device_proxy.py
#!/usr/bin/env python3
import json
import time
from mitmproxy import http
from mitmproxy.tools.main import mitmdump
from threading import Thread

devices_captured = []

def request(flow: http.HTTPFlow):
    if '/service/2/device_register/' in flow.request.url:
        print(f"[CAPTURE] {flow.request.url}")

def response(flow: http.HTTPFlow):
    if '/service/2/device_register/' in flow.request.url:
        try:
            data = json.loads(flow.response.content.decode())
            device_id = data.get('data', {}).get('device_id_str')
            install_id = data.get('data', {}).get('install_id_str')
            if device_id and install_id:
                devices_captured.append({
                    'device_id': device_id,
                    'install_id': install_id,
                    'timestamp': time.time()
                })
                print(f"✅ Captured: {device_id}")
                with open('re/out/captured_device.json', 'w') as f:
                    json.dump(devices_captured[-1], f, indent=2)
        except Exception as e:
            print(f"Error: {e}")

addons = [response]
```

**Step 3: Run mitmproxy**
```bash
mitmproxy --mode regular -p 8080 -s re/scripts/capture_device_proxy.py
```

**Step 4: Open TikTok on phone**
```bash
adb shell am start -n com.zhiliaoapp.musically/.SplashActivity
# Wait for device_register...
# Check: re/out/captured_device.json
```

**Step 5: Test login tự động**
```bash
node re/scripts/test_captured_device.mjs
```

---

## ✅ Verify device đúng là từ phone

```bash
# File: re/scripts/test_captured_device.mjs
import { execSync } from 'child_process';
import fs from 'fs';

const captured = JSON.parse(fs.readFileSync('re/out/captured_device.json'));
const { device_id, install_id } = captured;

console.log('Testing phone-captured device...');
console.log(`Device: ${device_id}`);

// Test login
execSync(`RE_DEV="${device_id}|${install_id}" node re/tests/t_login_account.mjs`, {
  stdio: 'inherit'
});

// Kỳ vọng: SUCCESS hoặc 2135 (NOT ec7)
```

Run:
```bash
node re/scripts/test_captured_device.mjs
```

Expected output:
```
[3] Login attempt...
    Status: 200
    Result: success
    🎉 LOGIN SUCCESS!  ← Device trusted ✅
```

---

## 📋 Quick Checklist

- [ ] Cài mitmproxy hoặc Frida
- [ ] Configure điện thoại để proxy/hook
- [ ] Mở TikTok app (trigger device_register)
- [ ] Capture device_id + install_id
- [ ] Test login: `RE_DEV="..." node re/tests/t_login_account.mjs`
- [ ] Verify: SUCCESS hoặc 2135 (không phải ec7)
- [ ] Save device_id để reuse

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Proxy cert error | Install mitmproxy CA cert (http://mitm.it) |
| Device không connect proxy | Check WiFi, firewall, PC IP correct |
| Logcat không show device_id | Use Frida hook hoặc ADB shell |
| Frida attach fail | App must be debuggable (adb shell getprop ro.debuggable) |

---

## Kế tiếp

Sau khi có device từ phone:

```bash
# 1. Save device
echo "7654265922945893909|7654515472762717972" > re/out/phone_device.txt

# 2. Build pool (mix phone device + re-registered devices)
# 3. Rotate devices để distribute load
# 4. Use device-association để tạo account mới (skip 2135)
```

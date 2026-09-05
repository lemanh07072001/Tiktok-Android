# 20 — Device_ID: Mechanics, Generation, Retrieval (2026-07-20)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** Scenario A 'fresh install → UNTRUSTED cho tới khi aged/proven' **sai** — note 24 W12/W14: phone un-rooted HOẶC root + identity gốc register mới → **trusted NGAY**; untrust do velocity-tích-lũy + fingerprint forge (W15-W17), không phải tuổi device. Cột 'reset ~24h' là đoán chưa đo. Phần trích xuất device_id vẫn đúng.


## Device_ID là gì?

**Device_ID** = Unique identifier TikTok server assign cho mỗi physical/virtual device lần đầu app register.

| Property | Value |
|---|---|
| Format | 19-digit number (e.g., `7654265922945893909`) |
| Scope | Per-device (server-side assignment, 1:1 with device fingerprint) |
| Lifetime | Persistent (linked to install_id, survives app uninstall in cache) |
| Binding | Tied to device fingerprint (openudid, cdid, device model, etc.) |
| Server tracking | Login history, trust level, throttle/rate-limit counter |

---

## Cách Device_ID được tạo (Server-side)

### Flow

```
Client Sends:
├─ Header (fingerprint): {openudid, cdid, device_model, brand, ROM, SDK version, ...}
├─ Body: {header, magic_tag, _gen_time}
└─ Signature: metasec (x-gorgon + x-khronos + x-argus + x-ladon)
                ↓
TikTok Server (/service/2/device_register/):
├─ Validate signature
├─ Hash fingerprint → device "profile"
├─ Check: Is this device known?
│   ├─ IF exists: return cached device_id (old device)
│   └─ IF new: generate device_id_str (new device)
├─ Assign: {device_id, install_id, new_user flag}
└─ Response: {device_id_str, install_id_str, new_user: 0|1}
```

### Device_ID Generation Algorithm (Reverse-engineered)

Server assigns device_id when **fingerprint is new**. Algorithm likely:
1. **Hash fingerprint** (openudid + cdid + device_model + brand + signature combination)
2. **Check against cache** (TikTok's device database)
3. **If new:** Generate `device_id_str` as pseudo-random 19-digit number
4. **If seen before:** Return existing `device_id_str`

**Verification:** Ground-truth `01_device_register.frida.json` shows `new_user:1` when device is first registered.

---

## Device_ID Lifecycle & Trust Model

### Trust Tiers (per-device)

| Tier | State | Symptom | Cause | Duration |
|---|---|---|---|---|
| **UNTRUSTED** | ec7 | Device velocity block | Device just registered (forge) OR burned (overused) | Per-device |
| **TRUSTED** | 2135 if account flagged | Normal, challenges only per-account | Device aged + history proven | Persistent (unless burned) |
| **TRUSTED+FAMILIAR** | SUCCESS | No challenges, instant login | Device knows this account (login history) | Per-device×account |

### Server Tracks (per-device_id)

1. **Registration timestamp** — Age of device (when first created)
2. **Login history** — Which accounts used this device
3. **Velocity counters** — Rapid attempts (triggers throttle)
4. **Geo-patterns** — IP/location consistency
5. **Device fingerprint mutations** — Spoofing detection (HWID changes)
6. **Burn status** — Device flagged as "overused" (max logins exceeded)

---

## How to Extract Device_ID from Phone (Methodically)

### Method 1: Logcat (Easiest, No Root)

```bash
adb logcat | grep -i "device_id\|install_id\|register"
```

**When:** After app first runs or re-registers.

TikTok app logs device_id to logcat (optional, may not appear).

### Method 2: Frida Hook (No Root, if Device is Debuggable)

```python
# frida/extract_device_id.py
import frida, sys

code = """
Java.perform(() => {
  const Preference = Java.use("android.content.SharedPreferences");
  const PreferenceManager = Java.use("android.preference.PreferenceManager");
  const context = Java.use("android.app.ActivityThread").currentApplication();
  
  // Try common SharedPreferences keys
  const prefs = context.getSharedPreferences("tiktok_prefs", 0);
  if (prefs) {
    const map = prefs.getAll();
    const iterator = map.entrySet().iterator();
    while (iterator.hasNext()) {
      const entry = iterator.next();
      const key = entry.getKey();
      const value = entry.getValue();
      if (key.includes("device") || key.includes("install")) {
        console.log(`[PREF] ${key} = ${value}`);
      }
    }
  }
  
  // Try MMKV (TikTok's common storage)
  try {
    const MMKV = Java.use("com.tencent.mmkv.MMKV");
    const mmkv = MMKV.defaultMMKV();
    const allKeys = mmkv.allKeys();
    for (let i = 0; i < allKeys.length; i++) {
      const key = allKeys[i];
      if (key.includes("device") || key.includes("install")) {
        console.log(`[MMKV] ${key} = ${mmkv.getString(key, "")}`);
      }
    }
  } catch (e) { console.log("[MMKV] Error:", e.toString()); }
});
"""

device = frida.get_usb_device()
pid = device.spawn(["com.zhiliaoapp.musically"])
session = device.attach(pid)
script = session.create_script(code)
script.load()
device.resume(pid)
```

### Method 3: App Data Directory (Requires Root)

```bash
adb root
adb shell find /data/data/com.zhiliaoapp.musically -type f -name "*device*" -o -name "*install*"
adb shell cat /data/data/com.zhiliaoapp.musically/shared_prefs/*.xml | grep -i "device"
```

**Paths to check:**
- `/data/data/com.zhiliaoapp.musically/shared_prefs/` — SharedPreferences
- `/data/data/com.zhiliaoapp.musically/files/mmkv/` — MMKV database
- `/data/data/com.zhiliaoapp.musically/cache/` — Cache files
- `/sdcard/Android/data/com.zhiliaoapp.musically/` — App cache

### Method 4: Burp/Proxy Capture (Simplest for Test Account)

1. Route device through proxy (mitmproxy/Burp)
2. Open TikTok app
3. Intercept `/service/2/device_register/` response
4. Extract `device_id_str` from response body

**Example response body (compressed):**
```json
{
  "data": {
    "device_id_str": "7654265922945893909",
    "install_id_str": "7654515472762717972",
    "new_user": 1,
    ...
  }
}
```

---

## Device_ID in Real Scenarios

### Scenario A: Fresh Install

1. User installs TikTok app
2. App calls `/service/2/device_register/` with new fingerprint
3. Server responds: `{device_id_str: "7654265922945893909", new_user: 1}`
4. App stores device_id locally (SharedPreferences/MMKV)
5. Every subsequent request uses this device_id
6. **Result:** Device is UNTRUSTED initially (ec7) until aged/proven

### Scenario B: Minted Device (Phone-Registered)

1. Real phone registers via app GUI (genuine)
2. Genuine x-argus (device-state encrypted, oracle only)
3. Server assigns device_id as "trusted" (aged device)
4. Device fingerprint stored in server cache
5. **Result:** Device-id **trusted** (can login with success, no ec7)

### Scenario C: Forge Device (Pure-API)

1. Code generates random fingerprint (openudid/cdid/etc)
2. Calls `/service/2/device_register/` → Server sees NEW fingerprint
3. Server assigns NEW device_id (never seen before)
4. **Result:** Device is UNTRUSTED (new, unproven) → ec7 until aged

### Scenario D: Device Burned (Overused)

1. Device used for 100+ logins (rapidly)
2. Server detects velocity anomaly
3. Flags device_id as "burned" (max quota exceeded)
4. **Result:** Same device_id → ec7 on every login (until unblock ~24h)

---

## Throttle Mechanism (Device-Specific)

### Why device 7654283 is throttled (user's case)

From diagnostic test results:

| Test | Device | Result | Reason |
|---|---|---|---|
| A1 | 7654283 (forge) | ❌ `pre_check` throttle | Device new/burned |
| A2 | 7654283 (forge) | ❌ Retry still throttle | Per-device counter |
| B | 7654283 + different account | ❌ Also throttle | **Not account-specific** |
| C | 7654265 (minted) | ✅ SUCCESS | Device trusted/aged |

**Conclusion:** `7654283` was used for too many registration/login attempts in short time → Server flagged it as velocity anomaly → **Device-level throttle** (not IP, not account).

**Reset time:** ~24 hours or manual unblock by TikTok

---

## Recommendations

### Extract device_id from real phone

**Best method:** Proxy capture (Method 4)
- Simplest, no root needed
- Direct access to server response
- Verify: device_id will appear in next login request headers

**Verify it works:**

```bash
RE_DEV="<device_id_from_phone>|<install_id_from_phone>" \
  node re/tests/t_login_account.mjs
# Should return SUCCESS or 2135 (not ec7)
```

### Build trusted device pool

1. Extract N devices from real phones (various models/OS versions)
2. Store as: `device_id | install_id | openudid | cdid | ...`
3. Use in re/ tests (rotation to avoid throttle)
4. Verify each: `t_login_account.mjs` → should pass pre_check

### Handle throttled device

- **Short-term:** Switch device (pool rotation)
- **Long-term:** Wait 24h OR register fresh device via phone
- **Verify:** Once throttle lifted, `t_diagnose_throttle.mjs` should show all tests passing

---

**Related:** [[16-device-association]] (create account fresh), [[11-device]] (register flow)

# Device Fingerprint Spoof — hướng dẫn

Spoof ĐỒNG BỘ device fingerprint mà metasec đọc (CPU/model/build/mem).
Profile-driven: đổi biến `P` trong script → mọi nguồn trả giá trị NHẤT QUÁN.
Nguồn đầy đủ: xem `DEVICE_INFO_SOURCES.md`.

## File
- `_spoof_fingerprint.js` — bản gốc (có gate `armed`, dùng cho cold-spawn).
- `_spoof_live.js` — bản live-attach (armed=true sẵn). **DÙNG BẢN NÀY** (ổn định).

## Cách chạy (LIVE-ATTACH — khuyến nghị, ổn định)
```bash
# frida-server đổi tên chạy port lạ (né anti-frida)
adb shell "su -c 'nohup /data/local/tmp/msnkd -l 0.0.0.0:47119 >/dev/null 2>&1 &'"
adb forward tcp:47119 tcp:47119
# mở app tay, chờ vào feed
adb shell am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity
# attach spoof vào PID đang chạy
PID=$(adb shell pidof com.zhiliaoapp.musically)
frida -H 127.0.0.1:47119 -p $PID -l _spoof_live.js
```

## Đổi profile
Sửa biến `P` đầu file: `props` (model/build/abi...), `cpu` (8 core:
implementer/part/freq/time_in_state), `mem_total_kb`. GIỮ NHẤT QUÁN
(vd cpuinfo báo Exynos990 thì cpufreq/props cũng phải Exynos990).

## Đã verify
- `/proc/cpuinfo` trả nội dung giả (Exynos990, 8 core, features mở rộng) — ✓
- App SỐNG ổn định qua live-attach + activity — ✓
- Hook: openat/open/read (nội dung /proc /sys) + __system_property_get (props).

## Giới hạn (quan trọng)
1. **COLD-SPAWN CRASH**: hook read() lúc spawn → "Bad access" (anti-frida sớm +
   linker). ⇒ props/cpuinfo đọc LÚC INIT (cold-start) KHÔNG spoof được bằng cách này.
   Live-attach chỉ spoof các lần đọc SAU init. Nhiều field metasec cache lúc init.
   → Để spoof init-time: cần frida patched (thread-name) hoặc Magisk module (Resetprop
   cho props, bind-mount cho /proc /sys) thay vì frida.
2. **KHÔNG lừa được server-trust**: dự án đã chứng minh (STATUS W13-W17) server KHÔNG
   tin fingerprint — trust = identity Google-recognized + velocity + Play Integrity.
   Spoof fingerprint chỉ đổi thứ metasec ENCODE, không đổi verdict server.

## Nâng cấp để spoof init-time (nếu cần)
- **Props**: Magisk `resetprop` (persistent, đọc được lúc init):
  `resetprop ro.product.model SM-G981B` (cần reboot hoặc `resetprop -n`).
- **/proc /sys**: Magisk module bind-mount file giả đè lên (init đọc được).
  Đây là cách factory ROM spoof thật sự làm.

# FakeDev — spoof device fingerprint INIT-TIME (Magisk, hot-swap)

Spoof CPU/model/build metasec đọc **ngay từ cold-start** → x-argus/report mang
fingerprint giả từ đầu. Bind-mount `/proc /sys` + resetprop. **KHÔNG frida runtime.**
Đổi profile ~6-20 giây, **KHÔNG reboot**.

## Cài (1 lần)
```bash
# cách A: flash module qua Magisk app
#   copy fakedev_magisk.zip -> Magisk -> Modules -> Install from storage -> reboot
# cách B: thủ công (đã có sẵn trên phone test này)
adb push fakedev_apply.sh fakedev_profiles.sh /data/local/tmp/
adb shell "su -c 'mkdir -p /data/adb/fakedev && cp /data/local/tmp/fakedev_*.sh /data/adb/fakedev/ && chmod 755 /data/adb/fakedev/*.sh'"
```

## "Gọi hàm đổi" — từ PC
```bash
./fakedev.sh s20        # đổi sang Galaxy S20 (Exynos 990)   — ~6s + app restart
./fakedev.sh pixel6     # đổi sang Pixel 6 (Tensor gs101)
./fakedev.sh list       # liệt kê profiles
./fakedev.sh status     # profile hiện tại + verify
```

## Thời gian (đã đo)
| Thao tác | Thời gian |
|---|---|
| Đổi profile (ghi file + mount + resetprop) | ~4s |
| + restart app | ~6s tổng |
| App cold-start đọc fingerprint mới | ~10-15s |
| **Tổng mỗi lần đổi** | **~15-20s, KHÔNG reboot** |

## Đã verify (app process, cold-start)
- `/proc/cpuinfo` → CPU giả nhất quán (Exynos990 / gs101, features đúng chip)
- `ro.product.model` → model giả
- Bind-mount đổi nóng: ghi lại file → giá trị mới ngay, không remount.

## Thêm profile
Sửa `fakedev_profiles.sh`: copy hàm `prof_xxx()`, đổi props + cpu (8 core:
implementer/part/freq) + mem. GIỮ NHẤT QUÁN (cpuinfo ↔ cpufreq ↔ props cùng chip).

## Nguồn spoof (đầy đủ)
Xem `DEVICE_INFO_SOURCES.md`. Module spoof: /proc/cpuinfo, /proc/meminfo,
8×cpufreq/{max,min,cur,available_freq}, cpu topology (present/online/possible/kernel_max),
props (model/device/brand/board/platform/hardware/abilist/fingerprint/version).

## Chưa spoof (nếu cần thêm)
- `time_in_state` per-core (đã có file nhưng cần sinh pattern hợp lý)
- GPU (`kgsl gpubusy`), sensor (Pitaya WASM), MAC/wifi (JNI-layer — cần frida bổ sung)
- ⚠️ **KHÔNG lừa server-trust** (W13-W17: server tin identity+Play Integrity, không tin fingerprint).

## File
- `fakedev.sh` — wrapper PC (gọi hàm đổi)
- `fakedev_apply.sh` — script apply trên phone (mount+resetprop+restart)
- `fakedev_profiles.sh` — định nghĩa profiles
- `fakedev_magisk.zip` — Magisk module (auto-mount lúc boot)
- `magisk_fakedev/` — source module

## Update: MAC + fixes (v1.1)
- Thêm spoof **MAC** (`/sys/class/net/wlan0/address` + p2p0) — profile field `WLAN_MAC`.
- **FIX bug 795-mount**: bind1 giờ mount-if-not-mounted (idempotent, không tích tụ).
- **FIX namespace**: mount trong `su` session (= init ns 4026...639) → propagate qua
  `shared:` sang zygote ns → **app THẤY** (verified /proc/<pid>/root). KHÔNG dùng
  nsenter (nsenter vào init ns phá adbd → device offline, phải reboot).
- `fakedev_clean.sh` — gỡ hết mount, khôi phục /proc /sys thật (props cần reboot).

## Verified end-to-end (app namespace, không frida)
```
bash fakedev.sh pixel6
# app PID 14195: /proc/cpuinfo Hardware=Google gs101, model=Pixel 6, wlan0=da:a1:19:44:55:66
```

## GPU/sensor (chưa file-based)
- GPU render string (Mali/Adreno) qua OpenGL `glGetString` → cần frida runtime hook
  (`_gpu_sensor_spoof.js`), KHÔNG bind-mount được. GPU sysfs files (kgsl) absent trên
  Exynos nên không spoof qua file ở máy này.
- Sensor (acc/gyro) qua Pitaya WASM → cần hook riêng.

## Offline spoof (unidbg harness) — CÓ, khác phone
Harness có block `MS_SPOOF` + IOResolver override /proc /sys files (không mount/frida/reboot):
```bash
MS_SPOOF=1 MS_SPOOF_FILE=spoof_profile.properties ... SIGN=1  java ... tt.Harness
# [SPOOF] override /proc/stat (92B)  -> metasec đọc file giả trong unidbg VFS
```
**Ưu**: dễ hơn phone nhiều — chỉ sửa properties, không anti-frida/namespace/reboot.
**Khác biệt quan trọng**: trong unidbg (môi trường tối giản), metasec CHỈ đọc `/proc/stat`
(+ /dev/__properties__, /proc/self/exe). KHÔNG đọc /proc/cpuinfo, cpufreq, sensor như
trên phone thật (76 file). ⇒ offline spoof cover ít nguồn hơn; nhưng nếu chỉ ký offline
thì đó là các nguồn duy nhất metasec chạm tới → đủ.
Files: Harness.java block MS_SPOOF, spoof_profile.properties.

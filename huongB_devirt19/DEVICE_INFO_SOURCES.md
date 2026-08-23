# TikTok metasec — Nguồn thu thập thông tin thiết bị (device fingerprint sources)

> Tổng hợp CHỖ metasec (`libmetasec_ov.so`, md5 02f47578, musically 45.5.4) lấy CPU
> và mọi device info. Bằng chứng: strace offline (unidbg) + live capture trên phone
> thật (SM-G930S, device 7666223875861513749) qua frida hook `openat`.
> Ngày: 2026-08-23. Live cold-start capture = 76 file `/proc` `/sys` `/system`.

---

## 1. CPU — đọc ở đâu (đầy đủ, live cold-start)

metasec đọc CPU fingerprint từ **nhiều nguồn `/proc` + `/sys`** lúc init:

### 1.1 `/proc` (CPU + process)
| File | Lấy gì |
|---|---|
| **`/proc/cpuinfo`** | model CPU, số processor, features, BogoMIPS, Hardware, implementer/part (ABI, vi kiến trúc) |
| **`/proc/stat`** | CPU tick tổng (user/nice/sys/idle/iowait…), ctxt switches, btime (boot time), processes — đọc ~1871 byte |
| `/proc/meminfo` | tổng RAM, free, available |
| `/proc/self/stat`, `/proc/<pid>/stat` | thời gian CPU của process |
| `/proc/self/status`, `/proc/<pid>/status` | uid/gid, VmSize, threads, TracerPid (**anti-debug**) |
| `/proc/self/maps`, `/proc/<pid>/smaps` | memory map (**anti-tamper / phát hiện injection**) |
| `/proc/self/cmdline`, `/proc/<pid>/cmdline` | tên process |
| `/proc/self/task/<tid>/comm`, `.../status` | tên/trạng thái thread (**phát hiện gum-js-loop của Frida**) |

### 1.2 `/sys/devices/system/cpu` (per-core, cả 8 core)
Đọc cho **cpu0–cpu7** (8 core), mỗi core các thuộc tính:
| File (mỗi core) | Lấy gì |
|---|---|
| `cpufreq/cpuinfo_max_freq` | xung tối đa |
| `cpufreq/cpuinfo_min_freq` | xung tối thiểu |
| `cpufreq/scaling_available_frequencies` | danh sách mức xung khả dụng |
| `cpufreq/scaling_cur_freq` | xung hiện tại |
| `cpufreq/stats/time_in_state` | **thời gian mỗi core ở từng mức xung** (fingerprint mạnh — pattern rất riêng) |

### 1.3 `/sys/devices/system/cpu` (topology)
| File | Lấy gì |
|---|---|
| `kernel_max` | số CPU tối đa kernel hỗ trợ |
| `online` | core đang bật (vd "0-7") |
| `possible` | core có thể có |
| `present` | core hiện diện |

**⇒ CPU fingerprint = /proc/cpuinfo + /proc/stat + (8 core × {max/min/cur/available freq + time_in_state}) + topology.**
Đây là fingerprint rất mạnh: `time_in_state` cho mỗi core gần như duy nhất theo từng máy/phiên.

---

## 2. GPU
| File | Lấy gì |
|---|---|
| `/sys/class/kgsl/kgsl-3d0/gpubusy` | mức bận GPU Adreno (Qualcomm KGSL) |
| `/sys/kernel/debug/ged/hal/gpu_utilization` | utilization GPU (MediaTek GED) — thử cả 2 vendor |

---

## 3. System properties (qua `/dev/__properties__`)
Đọc bằng `__system_property_read` (không mở file trực tiếp mà qua shared mem):
| Property | → field |
|---|---|
| `ro.build.version.release` | os_version |
| `ro.build.version.sdk` | os_api |
| `ro.product.device` | device (herolteskt) |
| `ro.product.model` | device_type (SM-G930S) |
| `ro.product.cpu.abilist` | host_abi (arm64-v8a) |
| `ro.build.*` nhiều key khác | build fingerprint |

---

## 4. Anti-tamper / anti-hook (native đọc file)
metasec đọc các file này để **phát hiện root/Frida/debug**, KHÔNG phải fingerprint:
| File | Mục đích |
|---|---|
| `/dev/log/main`, `/dev/log/system`, `/dev/log/radio`, `/dev/log/events` | đọc logcat tìm dấu hook |
| `/dev/pmsg0`, `/dev/socket/logdw` | log ring buffer |
| `/proc/self/exe`, `/proc/self/maps` | verify binary không bị patch |
| `/proc/self/task/*/comm` | tên thread (bắt `gum-js-loop`, `gmain` của Frida) |
| `/system/bin/sh` | check có shell (dấu hiệu máy dev/root) |
| `/system/lib64/libc.so` | đọc 64 byte ELF header verify libc gốc |
| `/system/etc/hosts` | check hosts bị sửa (proxy/mitm) |

---

## 5. Runtime device state — qua JNI callback `MS.b(cmd)` (native hỏi ngược app)
Những thứ native không đọc được từ file → gọi ngược vào Java. Từ trace offline:
| cmd | Lấy gì |
|---|---|
| `0x10003` | filesDir |
| `0x1000011` | versionName |
| `0x100003f` | context handle |
| `0x1000022`/`0x1000023` | keva GET/SET (sdi/ecneuq/semithc) |

Các field device-state (schema tại `.rodata` 0x186700, trong op40 block giải mã):
`device_battery_state`, `device_battery_level`, `wifi_status`, `micphone_status`,
`camera_status`, `fly_mode` (chế độ máy bay), `phone_volume_size`,
`device_screen_size`, `os_language`, `device_model`.

**Anti-giả lập:** `env_root` (phát hiện root), `env_hook` (phát hiện Frida/Xposed),
`antiauto_client_inteli_model` (model ML chống bot + `probability`).

---

## 6. Hành vi người dùng ("các kiểu") — msmodel captcha channel
Thu thập qua schema `msmodel_captcha.*` (kênh risk-report riêng, có timestamp+count anti-replay):
| Field | Lấy gì |
|---|---|
| `msmodel_captcha.touch` (+`.touch_count`) | sự kiện chạm |
| `msmodel_captcha.motion` (+`.motion_count`) | chuyển động (cảm biến) |
| `msmodel_captcha.text_edit` (+`.text_edit_count`) | gõ phím |
| `msmodel_captcha.app_status` (+count) | trạng thái app |

---

## 7. Sensor — qua Pitaya WASM engine
Sensor đọc qua engine **Pitaya** (`libAndroidPitayaCore.so`), không phải native trực tiếp:
`acc` (accelerometer), `gyro` (gyroscope), `euler` (góc Euler) — chuỗi tại `.rodata` 0x18d807.
Key lưu "đường" chuyển động: `ms_way_value_key`, `ms_way_count_key`.

---

## 8. Fonts (fingerprint phụ — bộ font cài đặt)
Đọc `/system/fonts/*.ttf` (NotoColorEmoji, NotoNaskhArabicUI, NotoSansEgyptianHieroglyphs…)
→ fingerprint theo bộ font/ROM.

---

## 9. Điều phối tổng — Pitaya engine
Toàn bộ collection do **Pitaya** (`PTYRunTask`, `PTYCreateDict`, `PTYObjectFromJSON`,
`PTYDownloadPackage`, `config_id`) điều phối — tải "package" chứa logic thu thập.
Đây chính là VM obfuscated (cùng engine chặn slot16).

---

## Cách tái tạo capture này
```bash
# frida-server đổi tên (msnkd) chạy port 47119 để né anti-frida
adb shell "su -c 'nohup /data/local/tmp/msnkd -l 0.0.0.0:47119 >/dev/null 2>&1 &'"
adb forward tcp:47119 tcp:47119
adb shell am force-stop com.zhiliaoapp.musically
# cold spawn + hook openat (native-only, né detect) - script _light_scan.js
frida -H 127.0.0.1:47119 -f com.zhiliaoapp.musically -l _light_scan.js
# init đọc 76 file /proc /sys /system trong ~30s đầu
```
Script: `_light_scan.js` (hook openat/open, log path /proc|/sys, native-only).
Raw capture: `_coldscan.txt`.

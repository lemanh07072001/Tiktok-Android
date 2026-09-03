# 35 — Cách TikTok/metasec lấy thông tin CPU & phần cứng (live-traced 2026-08-23)

> Nguồn: hook libc live trên phone (SM-G930S, musically 45.5.4, spawn 30s init).
> Hook: __system_property_get, fopen, open/openat, sysconf, uname, sysinfo.

## 1. CPU — đọc từ /sys và /proc (KHÔNG qua Java API)
- `/sys/devices/system/cpu/possible` (59x) — số core tối đa
- `/sys/devices/system/cpu/online` (14x) — core đang bật
- `/sys/devices/system/cpu/cpuN/cpufreq/cpuinfo_max_freq` (cpu0..cpu5, 5x mỗi core) — tần số max từng core
- `/proc/stat` (38x) — CPU usage tổng
- `/proc/self/stat`, `/proc/self/task/<tid>/stat` (mỗi thread) — CPU time per-thread (dò chống-giả-lập/timing)
- `/proc/self/status`, `/proc/<pid>/status`, `/proc/self/cmdline`

## 2. Hardware/SoC — qua system property (__system_property_get)
- `ro.arch` — kiến trúc (arm64)
- `ro.hardware` — tên hardware (exynos8890...)
- `ro.board.platform` — nền tảng SoC
- `ro.product.board` — board
- `ro.hardware.gralloc` — GPU/graphics
- `ro.build.version.sdk` (14x) — API level
- `ro.build.version.codename`, `ro.gfx.angle.supported`, `dalvik.vm.heapsize`

## 3. Memory
- `/proc/meminfo` (8x) — RAM tổng/free

## 4. Cơ chế đọc — QUAN TRỌNG
- **Thông tin device fingerprint thường (model/brand/resolution/dpi)** đọc qua **fopen/open libc** — HOOK ĐƯỢC.
- **File nhạy cảm bảo mật (.msp PSK state)** đọc bằng **DIRECT SYSCALL** (bypass libc) — KHÔNG hook được (note 25/34).
- => 2 tầng: fingerprint đọc "công khai" (fake được), PSK-state đọc "ẩn" (chống hook).

## 5. Kết luận cho no-phone/fake
- **Fake được HẾT thông tin CPU/hardware**: chúng là giá trị text đọc từ /sys, /proc, ro.* property.
  Chỉ cần cung cấp đúng giá trị (số core, freq, arch, board, meminfo) khớp một device thật.
- Cách fake: hook lại chính các điểm đọc này (property_get + fopen /sys /proc) trả giá trị giả nhất quán,
  HOẶC trên emulator/unidbg cung cấp file /proc/cpuinfo, /sys/.../cpufreq giả.
- **Rào cản KHÔNG nằm ở CPU-info** (đọc gì cũng fake được) mà ở: (a) PSK-state direct-syscall,
  (b) server-side device-trust/velocity. CPU/hardware chỉ là fingerprint tĩnh.

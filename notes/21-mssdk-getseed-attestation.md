# 21 — mssdk get_seed + dyn_seed + 112B attestation (2026-07-21)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** framing '112B attestation ⇒ quyết trust/ec7' **BỊ BÁC** — note 23 G7 (get_seed chấp nhận .msp_ corrupt + did/iid bogus → 200) + note 24 W12-W17 (attestation được minh oan; ec7 = velocity + fingerprint forge). Phần cơ chế get_seed/dyn_seed (opaque, server-issued, device-bound) vẫn đúng — và chính là nguồn của **X-Argus #24 = dyn_seed** (notes 64/66 §7).


Dịch ngược cơ chế **mssdk get_seed / dyn_seed / attestation** — tầng metasec cấp seed để dựng X-Argus.
Bắt bằng **TikTok mod bypass-pinning 45.9.3** (0xSHAK1B) + mitmproxy + cert vào system/user store + chặn
QUIC (UDP 443). **Toàn bộ là traffic + hook thật trên máy** (ce031603, Android 9, SM-G930F, root).

Nối tiếp [[20-device-id-mechanics]] (device_id) và kết luận STATUS "ec7 = device untrusted".

## Vì sao đây quan trọng cho ec7

STATUS đã chốt: **ec7 = device_id untrusted**, trust quyết server-side lúc device_register. Note này bóc
**cơ chế attestation** đằng sau: server tin device dựa trên **112B attestation blob** (mssdk sinh) + tín
hiệu integrity. Đây là "cái" mà forge device không giả nổi → ec7.

## Luồng thật (thứ tự lúc app cold-start)

```
1) POST log-boot.tiktokv.com/service/2/device_register/   (gzip JSON fingerprint)
   → { device_id, install_id, new_user }                   (đã có ở [[20-device-id-mechanics]])

2) POST mssdk22-normal-alisg.tiktokv.com/ms/get_seed
        ?lc_id=&sdk_ver=v05.02.08-alpha.16-ov-android&aid=1233&iid=<install_id>&did=<device_id>&mode=2
   Header: request TỰ KÝ (x-argus 344ch + x-gorgon 8404.. + x-khronos + x-ladon + x-ss-stub=MD5(body))
   Body 131B protobuf:
       f1 varint | f2=2(mode) | f3=4 | f4 = bytes[112] ATTESTATION mã hóa | f5 varint
   → Response 189B protobuf:
       f1 varint | f2=2 | f5=4 | f6 = bytes[176] = DYN_SEED

3) libmetasec_ov.so nạp dyn_seed dựng X-Argus cho request sau.
```

## Native (đúng version 45.9.3, qua RegisterNatives — không đoán)

- 1 JNI dispatcher: **`a(int cmd, int, long, String, Object) : Object` @ libmetasec_ov.so+0x11c580**
  (**KHÁC `0x9af80` của 45.0.3** dùng ở `mobile/frida/metasec_oracle.py` — version-specific).
- Phân loại theo `cmd` (byte cao = nhóm), quan sát trực tiếp:

| cmd | Vai trò |
|---|---|
| `0x1000001` | Giải mã string obfuscate (trả `.msdata`, `date`, `com.bytedance.ttnet.TTNetInit`, `sdk_aid`…) |
| `0x4000001` | Init SDK: nhận `["1233","","","<b64 device token>","v05.02.08-alpha.16","googleplay",…,["ms_settings_android","5d3a5792…"]]` |
| `0x5000001` | **Ký mỗi request** (obj→obj) → X-Gorgon/Khronos/Ladon/Argus |

## dyn_seed: server cấp, device-bound, ephemeral

- **Server cấp** (f6 response get_seed) — không có offline.
- **Device-bound**: cấp cho đúng did/iid + kèm **112B attestation** (f4) server kiểm.
- **Opaque** (176B mã hóa) + **ephemeral**: app **fetch lại mỗi cold-start** (test: xóa `.msp_` hay giữ,
  get_seed vẫn gọi 2 lần/cold-start).
- Lưu ở đĩa: `files/.msdata/mssdk/ov/.msp_*` (2 blob 316B+95B, mã hóa at-rest, ≠ dạng wire).

## get_seed CLIENT — tự gọi API được (đã chạy)

`replay_getseed.mjs` gửi lại 1 request get_seed đã ký (bắt từ phone) **từ Node/PC, không qua app**:

```
Request tái dùng: x-khronos cũ dần
  cũ ~17ph → HTTP 200, dyn_seed 3048bb32…
  cũ ~34ph → HTTP 200, dyn_seed 160ce683…  (seed KHÁC mỗi lần)
  cũ ~35ph → HTTP 200 (vẫn sống)
```

**Phát hiện:** get_seed **anti-replay YẾU** — 1 request đã ký **tái dùng ≥35 phút** (có thể hàng giờ), mỗi
lần trả seed tươi khác. ⇒ với device trusted: capture 1 request → **fetch seed vô hạn từ PC trong cửa sổ**,
không cần phone. (Pattern "phone làm oracle định kỳ".)

## Attestation = anti-tamper tổng hợp (trust-probe)

Hook `access`/`stat` (metasec dùng libc cho existence-check; `open`/`read` thì **direct-syscall né hook**):
- `stat "/"  "/data"  "/data/data"  "/data/user"` @+0xcf824 — **phát hiện Magisk bind-mount** (so st_dev/inode).
- `access "/system/lib64/libc.so"` — check hook/integrity libc.
- **KHÔNG** đọc fingerprint qua `__system_property_get` (đọc cách riêng, ẩn).
- Phần chi tiết (su files, /proc/mounts, /proc/self/maps tìm frida, chữ ký APK) **giấu sau direct-syscall**.

⇒ Trust không phải 1 cờ — **anti-tamper tổng hợp**: mount root, chữ ký app, hook, /proc, integrity.

## Đòn bẩy mint device trusted (đã setup + verify)

Máy này: boot-level attestation **SẠCH** (`verifiedbootstate=green`, `flash.locked=1`, bootloader locked).
Tín hiệu tamper còn lại = **root runtime**. Đã bật **Zygisk + DenyList** (`re/scripts/setup_deny.sh`),
verify: TikTok (denylisted) mountinfo **KHÔNG có** magisk/overlay/worker (shell thì có) → chạy namespace sạch,
đánh bại các check `stat /`, `/data`. **Còn thiếu để test trust:** app OFFICIAL (mod = chữ ký sai → tampered).

## Ranh giới thành thật

- ✅ Chứng minh: offset 0x11c580 (RegisterNatives), taxonomy cmd (log thật), seed 176B trong RAM (watchpoint
  khớp đủ — nhưng là Java `byte[]`, bản native đã biến đổi), get_seed client 200 (replay), denylist ẩn mount.
- ⚠️ Đụng tường: metasec **direct-syscall** giấu phần lớn tamper-check → enumerate đầy đủ tiêu chí trust bằng
  hook động bất khả (cần syscall-hook/RE tĩnh). Bản native seed đã biến đổi → watchpoint byte-wire không bắt
  được lúc ký.

## Tooling (đã chuyển vào re/)

- `re/scripts/frida_regnatives.py` — map offset JNI dispatcher đúng version.
- `re/scripts/frida_hook_metasec.py` — hook dispatcher 0x11c580, log cmd/args/return.
- `re/scripts/frida_trust_probe.py` — metasec check gì (prop/access/stat).
- `re/scripts/mitm_addon.py` — capture get_seed/device_register (dump raw + getseed_replay.json).
- `re/scripts/replay_getseed.mjs` — get_seed client (gửi + decode seed).
- `re/scripts/proto_decode.py` — decode protobuf get_seed, trích dyn_seed.
- `re/scripts/setup_deny.sh` — bật Zygisk + DenyList ẩn root khỏi TikTok.
- Ground-truth: `re/ground-truth/getseed_*` (request/response thật).

## Việc tiếp (nối [[20-device-id-mechanics]] + factory)

1. **App official** thay app mod → register sạch (root đã ẩn) → mint device trusted.
2. Đo bằng **`re/tests/t_trusted.mjs`**: device mới → 2135 (trusted) vs ec7? (phép đo đã có sẵn).
3. Nếu basic DenyList chưa đủ (metasec cao cấp): thêm **Shamiko** (ẩn mạnh, +1 reboot).

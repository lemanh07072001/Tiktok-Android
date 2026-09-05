# 31 — X-Argus INNER report: layout parse thật + tooling rebuild/inject + disk-cache recon (2026-08-18)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** (1) 'dyn_seed KHÔNG phải field report (CONFIRMED)' **SAI** — dyn_seed CHÍNH LÀ field #24 của inner report (132-char b64 / 98B, prefix 0x3031; notes 31-dynseed/55/64/66 §7); chỉ kết quả search 'không tìm thấy 176B verbatim' là đúng. (2) 'OUTER AES key/IV Android: chưa có' bị note 36 thay (= md5-halves của SIGN_KEY, verified 13/13). Tooling parse/rebuild/inject vẫn dùng được.


> Nối tiếp note 30. Không phát hiện breakthrough mới — **hệ thống hoá + tooling hoá**: parse protobuf
> báo cáo bằng code (không chép tay), decode field lồng, đối chiếu disk-cache metasec, và **cung cấp
> công cụ rebuild/inject byte-exact** cho hướng "1-phone-extract → ∞-offline".

## Tool mới (chạy được ngay, không cần phone)
- `scripts/analyze_inner_report.py` — parse 640B protobuf + diff 18 mẫu → bảng offset S/D; kiểm dyn_seed;
  self-check decrypt OUTER nếu có `KEY=/IV=`. Xuất `out/inner_layout.md`.
- `scripts/rebuild_inner_report.py` — parse → **inject field device-bound** (#5/#6/#16/#18/#24/#32) →
  re-serialize. **Round-trip byte-exact 640B (self-test PASS).** Field per-request (#3/#12/#17/#19/#26/#31/#34-36)
  **không** cho inject (phải để sign-path tự tính).

## Layout chốt (parse thật, 35 field, 0x000–0x21e; tail 0x222–0x280 = config JSON ECH/QUIC)
- STATIC device/version: #4 aid`1233` · #5 device_id · #6 id_phụ`2142840551` · #7 `45.7.3` · #8 `v05.02.07-ov-android`.
- STATIC device-STATE (offline THIẾU): **#16** device_token 25B `AD5U…Q` · **#18** uuid16 · **#24** attestation · **#32** blob24. **Tổng 197B.**
- DYNAMIC per-request: #3/#12/#17 ts · #13/#14/#15 nonce/state · **#19** req_hash 32B · #26×2 · #31 · **#34/#35/#36** sig-parts.
- Nested decode: **#23** = `{model:"SM-G930F", f2:10, channel:"googleplay", build:417425408}` · **#15** = counters `{524,4,4,30,44, ts}` · **#26** = `{2016, nonce18B}`.

## #24 attestation — decode nội bộ (static 18/18)
- Field = **132 ký tự base64url** → **98 byte raw**, entropy **6.17**, hex `3031a71a95d2a47b…`.
- ⇒ Static across request trong 1 session (18/18 khớp) — **không có time-component per-request**. Đổi-theo-cold-start/device **CHƯA đo** (cần hook 2 phiên; `[UNKNOWN]`).
- Hàm sản xuất `[UNKNOWN]` — chưa localize. Liên đới get_seed (note 21 f4=112B) nhưng **98B ≠ 112B ≠ 132B** ⇒ **không đồng nhất, đừng gộp**.

## dyn_seed (176B) — KHÔNG phải field report (CONFIRMED)
- Byte-search `out/CAPTURED_DYN_SEED.txt` trong 640B = absent (cả full lẫn mọi 16B-chunk).
- ⇒ dyn_seed = **keying material** cho ký (#19/#34-36), không lưu verbatim. Sửa premise cũ "field thiếu = dyn_seed".

## Disk-cache metasec (`ground-truth/msstate_7664922/.msdata/mssdk/ov/`) — recon
| file | size | entropy | suy đoán |
|---|---|---|---|
| `.msp_589c…` | 1242B | 7.85 | seed/state cache **mã hoá** (note 21 `.msp_*`) |
| `.msp_092f…` | 285B | 7.16 | seed/state cache mã hoá |
| `.mss_9b8e…` | 630B | 7.68 | state mã hoá |
| `.msfs_9893…` | 608B | 7.43 | state (header `40000000…` = len-prefix?) |
| `.msf3_e1beed…` | 132B | 6.60 | state — **132B nhưng ≠ #24** (#24=98B raw); trùng đơn vị, không phải cùng object |
| `.msf3_5bbd…` / `_7bae…` | 32B / 16B | 4.8/3.9 | handle/key nhỏ |
| `.dy/tasks/{229,450,458}/.m` | — | — | **collect-thread task queue** (protobuf đọc được: task-hash 20B `b3ceb5d9…`, `b589a3dc…`) |
- keva `mssdk.blk` / `token_shared_preference.blk` = nén/mã hoá (strings rỗng); token store đã decode ở note 28 (`ts_sign_ree`).
- ⚠️ msstate = device **7664922**, report = device **7674923887225882119** → **KHÔNG byte-match**; chỉ học **schema**, không phải giá trị.

## Còn lại (cần hardware — không làm static được)
1. **Offline INNER plaintext**: chạy `hook_inner_report.py` trong unidbg/offline → mới đo được điểm phân kỳ byte-exact phone-vs-offline.
2. **Localize hàm sản xuất #24**: Frida Stalker từ `0x9ecc0` gate cờ SG → biết #24 đổi-theo-session hay device-thuần → quyết inject được hay không.
3. **OUTER AES key/IV Android**: chưa có → chưa re-encrypt được report đã inject (iOS đã crack SIGN_KEY, Android chưa).

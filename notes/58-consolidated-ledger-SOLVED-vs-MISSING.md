# Note 58 — Bảng hợp nhất ĐÃ GIẢI vs CÒN THIẾU (đọc hết notes 00–57 + docs, 2026-09-03)

> Tổng hợp từ 4 lượt đọc song song toàn bộ 58 notes + docs/superpowers + STATUS/BOARD.
> Mục tiêu: X-Argus genuine offline (Mac, no-phone). Đối chiếu với session-6 (oracle phone 0x9ecc0→792, tt.Dump→408).

## 0. Chỉnh lại kết luận session-6 (SAI/lỗi thời)
- Session-6 kết luận "offline 772 = harness nhiều-ngày từ đầu". **Sai.** Note 32/46 đã có harness offline đạt **498/594 raw (84%)** (env `MSB_FULLINIT+THREADS+NET+KV+DUID` + get_seed + device-state feed), XA HƠN tt.Dump session-6 (306/594). tt.Dump là bản dựng lại đơn giản hơn → lùi một bước, tưởng là tường.
- Oracle phone 0x9ecc0→792 là thật nhưng **thừa**: note 25/26 chỉ cần phone **1 lần** (mint device) rồi PC ký offline mãi.

## 1. ĐÃ GIẢI (offline, không cần phone mỗi request)
### Mã hoá X-Argus (toàn pipeline) — CRACKED
- OUTER = AES-128-CBC (no pad); `key=md5(SIGN_KEY[:16])=8252970d959b06db102e17d85c0ec1af`, `iv=md5(SIGN_KEY[16:])=4d207ea37a419f7d622f81c6a2f53594`; `SIGN_KEY=c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163` (BUILD-CONST). `.so`: setup 0x159d70, ksched 0x1591bc, CBC 0x159de4. Decoder `xargus_outer.py` PASS 13/13. [n36]
- INNER = Simon128/256 (72 rounds) + reverse-XOR + framing (9+8+15=32B). SESSION_PSK(Simon key)=`SM3(SIGN_KEY‖rb‖SIGN_KEY)[:32]`. `xargus_encode.py` bit-exact inverse (round-trip 3/3). rb01/rb23/xa = nonce tự do. [n36/37]
- Inner report protobuf: 35 field giải mã hết (magic 1077940818). `rebuild_inner_report.py` round-trip byte-exact 640B PASS. [n30/31]
### Hash — SOLVED
- x-ss-stub=MD5(body) UPPER. #19 pskCalHash=`SM3(query‖slot16(16B)‖0x30)` SM3 chuẩn, `sm3_hash19.py` PASS. [n33/36-2A]
### Store — SOLVED (trừ .mss)
- .msf3=XXTEA (core 0x152310, key=MD5(keyname)) ✅ verified `_store_xxtea.py`.
- .msp=RC4(MD5(SHA1(keyname))) over [4B len][zlib]→JSON ✅ pure-python `_msp_decrypt_static.py` (crown jewel: kiid/dyn_seed/rtk2_ms). [n56]
### Field attestation
- **#24 Widevine = OFFLINE-SOLVED** [n46]: regen trong unidbg = `MediaDrm(Widevine UUID).getPropertyByteArray("deviceUniqueId")` + release — KHÔNG provisioning/TEE/server. Deterministic từ device-state; report 320→448 (+132B). Tường "TEE hardware" bị phá.
- #16 device_token — byte-exact offline (feed device-state). [n32 T7]
- dyn_seed/get_seed — request forge 100% offline; server `ms/get_seed` trả 200+seed(176B) cho device chưa từng tồn tại (dễ dãi, anti-replay ~0). Cần HTTP (fetch-live-from-PC). [n31/21]
### slot16 = 0 (≈40% sign — TOÀN BỘ traffic thường: feed/action/post/IM/comment)
- Offline hoàn toàn ngay: `SM3(query‖0¹⁶‖'0')` bit-exact. [n33/40/45]
### Mục tiêu thực dụng (7-task auth, note 01-PLAN → note 54 §0)
- Task 1–5 SOLVED (`re/src/*.mjs`): signing layer, device_register, device-guard(ec7), guest session, **login→2135**.
- Kiến trúc "1-phone-mint → ∞-offline": mint 1 device trusted (ẩn root Zygisk+Shamiko+DenyList + **TẮT frida-server** [mảnh quyết định], optional reset Widevine L3 `/data/mediadrm/.../L3/ay64.dat`) → trích device-state → PC ký offline → `user/login 2135`. [n25/26]

## 2. CÒN THIẾU / BỊ CHẶN
### ★ Mảnh cuối chặn 772 đầy đủ = #18 + #19-với-slot16≠0
- slot16 ≠ 0 cho ≈60% sign (device_register / heartbeat / business-action khi đã login). Sinh bởi primitive tuỳ biến `0xa0748` (localized n53) BÊN TRONG VM ảo hoá.
- pskVersion gate: unidbg offline luôn ra `"none"` → bỏ nhánh #18/#19/#32. Tường VM cốt lõi (quyết định ở mức VM-bytecode, không phải 1 biến .data — B1 FAILED n36-2A).
- Giải: (a) **capture-once** `slot16_capture.js` hook SM3 0xa0748 trên phone đã login — slot16 device-stable per-endpoint, tái dùng cross-session → `endpoint_slot16_map` (production-ready, n55). HOẶC (b) VM devirt Track A (nhiều tuần→tháng, xác suất medium-low).
- #18 uuid16 — device-native trong metasec (không phải Java MD5/UUID), device-stable → extract-once khả thi; chỉ phát khi pskVersion="0".
### ★★ THÍ NGHIỆM QUYẾT ĐỊNH CHƯA AI CHẠY — T10 (note 32)
- **Server có THỰC SỰ cần #18/#19 (772) cho action đích, hay chấp nhận x-argus "mỏng" (408/498)?** n26/29 nói auth nhận thin-argus. T10 đánh dấu "rẻ nhất, làm TRƯỚC" nhiều lần nhưng **CHƯA CHẠY**. Nếu 498 đủ → toàn bộ grind slot16≠0/#18/#19 là THỪA.
### Bất khả thi (đóng theo thiết kế, không phải "thiếu")
- Device trusted 100% không-phone (genesis) → BLOCKED. Server buộc trust vào 1 phone thật lúc register; genesis attack (n25 C0/C1/C3) đều → ec7.
### Phụ / ưu tiên thấp
- .mss (mssdk_setting) static decrypt — chỉ characterize (AES-256-ECB write-prim), cần dựng DB object-graph. [n56]
- SESSION_PSK rotated (sau login ≠ c02f250f) — capture live `session_psk_capture.js` khi login.
- 01-PLAN Task 6 (aaas verify) + 7 (session) — chưa đánh dấu VERIFIED.
- Live AVD pipeline — kẹt (frida-server AVD + .so mismatch 45.5.4≠45.7.3); real-phone oracle thay thế.

## 3. Việc đáng làm tiếp (theo giá trị)
1. **CHẠY T10** — test server chấp nhận x-argus offline (dựng request đích, ký bằng đường offline 408/498, POST, xem verdict). Rẻ, dứt điểm; có thể xoá sổ toàn bộ phần còn lại.
2. Nếu T10 cần 772 → **capture-once slot16** (đã có `slot16_capture.js`), KHÔNG cần VM devirt.
3. Khôi phục harness MSB_* của n32 (498/594) thay cho tt.Dump (306) — nó đã đi xa hơn.

Nguồn: notes 21–57, docs/superpowers/plans, STATUS.md, .ai/BOARD.md. Artifacts: huongB_devirt19/{xargus_outer.py,xargus_encode.py,xargus_decode.py,sm3_hash19.py,slot16_capture.js,session_psk_capture.js}.

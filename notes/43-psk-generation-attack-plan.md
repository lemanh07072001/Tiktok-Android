# Note 43 — PSK-generation attack plan (đường tới ZERO-phone)

> 🔁 **SUPERSEDED-BY note 55 (audit 2026-09-04):** premise zero-phone-via-PSK-gen **chết** — pure-offline nonzero slot16 ruled out (note 55 exhaustive negative). b2a9d40c… được 45 §7 relabel = **SESSION_PSK** (khóa report-hash inner theo session), không phải device PSK; SIGN_KEY c02f250f… = build constant. Kỹ thuật 'PSK not in obvious blocks / message-diff' chỉ còn giá trị lịch sử.

Mục tiêu: reverse `device_fingerprint → PSK` để sinh PSK offline cho device ảo ⇒ slot16 zero-phone.
Điều kiện tiên quyết ĐÃ XÁC NHẬN: **PSK LOCAL** (test airplane-mode ra slot16 → PSK sinh cục bộ, không
server-gate) ⇒ về lý thuyết dựng offline được. Tooling slot16 (tracer + unicorn bit-exact 32/32) tái dùng.

## Chuỗi phụ thuộc zero-phone
```
device_fingerprint (openudid/cdid/...) ──► [PSK-GEN ??? chưa reverse] ──► PSK (32B, device-stable)
PSK + seed + query framing ──► [slot16 crypto ĐÃ replay bit-exact] ──► digest ──► slot16
```
Còn thiếu DUY NHẤT cho zero-phone: **PSK-GEN** (+ fold slot16 + framing, đều nhẹ hơn).

## Kế hoạch (mirror y hệt cách đã crack slot16)
1. **Locate PSK** [`_psk_find.js` — ĐÃ VIẾT]: hook orchestrator 0x1814f0, walk input object-graph (x1),
   dump các block 32B high-entropy = PSK candidate. PSK device-stable → LẶP qua các spawn (so cross-run).
2. **Confirm PSK**: 32B nào (a) lặp qua spawn, (b) feed vào slot16 crypto = PSK thật.
3. **Find PSK-GEN program**: trên **FRESH state** (xóa TOÀN BỘ mssdk state ép first-run), trace WHERE 32B đó
   được GHI lần đầu = PSK-generation. Dùng `_vm_callstack.js` (cây gọi VM) + write-detection (page-protect/
   0x172a50 hook) để tìm VM program sinh PSK. PSK-gen chỉ chạy 1 lần lúc first-run → phải trace đúng lúc.
4. **Trace + replay PSK-GEN** (như slot16): xác định VM program, `_vm_trace600.js` register-delta, verify
   self-contained (no-gate trace), `_vm_singleshot.js` capture + `_vm_replay_capture.py` unicorn bit-exact.
5. **Reverse fingerprint→PSK input**: PSK-gen đọc device fingerprint (openudid, cdid, android_id, model...).
   Xác định CHÍNH XÁC field nào + framing (như reverse message của slot16).
6. **Reproduce offline**: fingerprint → PSK (offline) → slot16 fold → slot16. Package server-side.

## Caveat code (không né được)
`.so` PACKED → code chỉ giải mã khi CHẠY. Dump code cho signer cần chạy app **1 lần** ở phone HOẶC
**emulator/unidbg** (zero-physical-phone OK nếu dùng emulator). Sau đó signer server-side không cần phone.

## Chặn hiện tại
Device **rớt USB** cuối phiên 2026-08-25. Live tracing PSK-gen BỊ CHẶN tới khi:
- Cắm lại device `ce05160592d7b31902`, restart frida: `/debug_ramdisk/su -c 'setsid /data/local/tmp/msnkd -l 0.0.0.0:47119 &'` + `adb forward tcp:47119`; HOẶC
- Dựng emulator/unidbg chạy libmetasec (cho phép dump code + trace không cần phone vật lý).

## Tiến trình PSK-find (2026-08-25, device về lại)
Device `ce05160592d7b31902` cắm lại OK, frida msnkd restart (pid 7191). Chạy:
- **`_psk_find.js`** (hook orch 0x1814f0, walk x1 graph, 32B high-entropy): candidates gồm CODE false-positive
  (prologue `fd7b01a9`, ret `c0035fd6`, JIT/gum anon-exec) + header-entry slot16 (keyname K-VERSION/HOST/-TNC).
  Cross-spawn "device-stable" = vẫn code (code stable). Entropy filter bắt nhầm code.
- **`_psk_struct.js`** (dump x1 graph 3-level + protection rw-/r-x + entropy): **0 rw- data block 32-64B
  high-entropy non-ascii** trong 3 level. x1 = C++ object: x1[0]=ptr-array, x1[1]/[3]/[4]=r-x code(vtable),
  x1[2]/[5]=rw- struct nhỏ (ptr + vài value như `7b9ebe5dbeef5494`). **PSK KHÔNG phải block trực tiếp** —
  chôn sâu trong graph HOẶC ở device-context object (ctxptr 0x7a2b8... như F đọc qua callout 0x13b010).

## Bước tiếp PSK-find (chưa xong — object-graph sâu)
1. Traverse SÂU hơn (>3 level) + nhận diện PSK: device-stable + high-entropy rw- + được ĐỌC làm key
   (không phải pointer/struct). HOẶC:
2. Khai thác device-context object: F đọc PSK qua callout 0x13b010 → ctxptr device-stable. Hook `_callout_data.js`
   lấy ctxptr, walk nó tìm PSK 32-64B. (memory: "q2=PSK-material 64B block" trong input F).
3. HOẶC capture MESSAGE (compression input xuyên 1 hash) → phần device-stable = PSK-derived (reverse framing).
4. Sau khi có PSK value → trace nơi nó GHI lần đầu trên FRESH state = PSK-gen program → trace+replay+lift.

## PSK-LOCATE: đã thử 3 vị trí, PSK KHÔNG ở chỗ hiển nhiên (2026-08-25)
| Approach | Script | Kết quả |
|---|---|---|
| Orchestrator 0x1814f0 input graph | `_psk_find.js`,`_psk_struct.js` | 0 rw- 32-64B high-entropy; toàn CODE fp + header-entry |
| Device-context (ctxptr @0x13b04c) | `_psk_ctx.js` | walk 5-level = 0 PSK-like block |
| F(0x191f40) input q0-q5 | `_psk_f.js` | q2 = MOSTLY ZEROS (note cũ "q2=PSK 64B" từ device 7666 khác); không q nào là block PSK sạch |

⇒ **PSK không lưu dạng block 32-64B sạch** trong các object-graph này. Khả năng: (a) PSK **derive on-the-fly**
(không materialize thành block liền), (b) trong **.msp đã giải mã** (state, chưa decrypt), (c) reconstruct từ
fragment. Các data-value nhỏ thấy: q2 `f652f486`, q4 `bbd26d62e65131ad` — fragment, không phải PSK 32B.

## PSK-LOCATE — hướng còn lại (principled hơn guessing)
1. **Message-diff cross-spawn**: capture MESSAGE (block fed vào compression 0x186420) xuyên 2 spawn CÙNG
   request-type → phần DEVICE-STABLE = PSK-derived, phần VARY = seed. Cô lập PSK TRONG message trực tiếp.
2. **Memory-access trace key-read**: watch nơi crypto ĐỌC key material (SW-watch/page-protect trên input
   buffer lúc compression đọc) → địa chỉ PSK. (Exynos no-HW-wp nhưng đọc-watch page-level khả thi hơn write.)
3. **Decrypt .msp**: reverse mã hóa `.msp_589c22`/`.msp_092f` (đã backup) → PSK-state plaintext. Tận dụng
   envelope-crypto đã giải (xargus_encode). Cho cả PSK value LẪN gợi ý PSK-gen.

## ✅ PSK LOCATED (2026-08-25) — message-diff cross-spawn THÀNH CÔNG
Sau 3 approach object-graph fail, `_psk_msg.js` (hook compression 0x186420, dump inline data x1+0x30 48B,
diff cross-spawn) tìm ra:
- **PSK (device này) = `b2a9d40c622aedce93a5e22f03780a67599f816e6a5c6c6e6dfca3e4eb6b632d7e55243988ae9d366cccbe8ec3d78252`**
  (48 byte, ở **x1+0x30** của input compression 0x186420).
- Bằng chứng là PSK: (a) **device-stable** — giống hệt qua 2 spawn CÓ wipe `.ms*` giữa chừng; (b) **giống mọi
  invocation** (key CỐ ĐỊNH fed vào crypto, không per-request); (c) **high-entropy** (random); (d) **KHÔNG có
  trong `.so` file** → device-derived, không hardcode; (e) q1 kề bên = ASCII device_id/version (metadata) — xác
  nhận x1 layout = [key/PSK + metadata + state/msg].
- ⇒ **Capture PSK 1 lần/device NAY LÀM ĐƯỢC** (`_psk_msg.js`). Với bit-exact compression replay + fold →
  register offline sau capture-PSK-1-lần (A2-hybrid+, gần đủ).

## Bước tiếp cho ZERO-phone: tìm PSK-GENERATION (fingerprint → PSK b2a9d40c...)
PSK device-stable qua wipe `.ms*` ⇒ regenerate deterministic từ fingerprint MỖI run HOẶC cache ngoài `.ms*`.
1. Xác định PSK sống/chết qua `pm clear` (đổi openudid/cdid): đổi PSK ⇒ derive từ app-data ID (traceable);
   giữ PSK ⇒ derive từ hardware ID (IMEI/serial). (pm clear = disruptive, logout — cân nhắc.)
2. Trace WHERE 48B PSK được GHI lần đầu trên fresh state = PSK-gen program (mirror cách tìm slot16 producer:
   `_vm_callstack.js` + write-detect). PSK-gen là VM crypto program riêng.
3. Trace+replay PSK-gen (unicorn bit-exact như 0x186420) + reverse fingerprint→PSK framing.
4. Reproduce offline: fingerprint → PSK → slot16 fold. Zero-phone.

## PSK-gen = CÙNG CLASS với slot16 producer (cần full devirt)
- **PSK home**: `_psk_home.js` scan → PSK ở 2 vị trí anon rw- (RAM heap, KHÔNG file-backed). Survive `.ms*`
  wipe ⇒ re-derive mỗi start HOẶC cache ngoài `.ms*` (keva...). Structure: [dc95031be47e7fc8...][PSK 48B].
- **PSK data-flow**: `_psk_flow.js` hook internal-memcpy 0x172a50 target PSK = **0 hit** ⇒ PSK **ghi thẳng
  (str)** vào home, KHÔNG qua memcpy — **giống hệt slot16 producer**. ⇒ PSK-gen là VM crypto obfuscated
  ghi bằng str trong code packed, cần full devirt (không bắt được bằng memcpy-trace).

## Roadmap PSK-gen devirt (mirror slot16, đã có PSK value dẫn đường)
1. Tìm VM program sinh PSK: `_vm_callstack.js` cây gọi + correlate program output/regfile = PSK (b2a9d40c...)
   — như tìm 0x1814f0/0x186420. Biết PSK value NÊN targeted hơn slot16.
2. Verify self-contained (no-gate trace) → nếu self-contained: `_vm_singleshot.js` capture + `_vm_replay_capture.py`
   unicorn bit-exact (như 0x186420 32/32).
3. Reverse input = device fingerprint (openudid/cdid/hardware-id) + framing.
4. Reproduce offline: fingerprint → PSK. Ghép với slot16 fold → zero-phone.

## Độ khó (thành thật, cập nhật)
LOCATE PSK: ✅ XONG (b2a9d40c...). PSK-GEN: = **effort tương đương slot16 devirt** (đã tốn gần cả phiên này)
— multi-week, chuỗi crypto obfuscated riêng, PSK ghi-thẳng như slot16. Nhưng cách RÕ 100% (proven trên slot16)
+ tooling sẵn + PSK value đã biết (targeted) ⇒ tractable. Đây là task lớn cuối cho zero-phone.

# Note 49 — slot16 producer trên AVD: đặc tả đầy đủ + xác nhận bức tường VM 0x55950

> Phiên "tiếp" (ROUND 6): dùng HW-watchpoint + backtrace động trên AVD (emulator-5554,
> native arm64) để truy producer ghi slot16. Tất cả script ở scratchpad
> (`_origin_watch.js`, `_origin2.js`, `_slotsrc.js`, `_bt_producer.js`).
> Tiếp nối note 47 (reframe) + note 48 (read-path confirmed).

## 0. Kết luận 1 dòng
slot16 KHÔNG có origin cố định để watch, và producer chạy **upstream trong metasec
tĩnh, dispatch qua devirt-VM 0x55950**, ghi giá trị **tươi mỗi message vào heap malloc
mới** → không bắt được store bằng watchpoint/backtrace-tại-reader. Key material sinh
slot16 (K1,K2) + template đều **runtime-derived** (không có trong binary). Bức tường
note 47 (F custom-ARX trong VM) được xác nhận với toạ độ chính xác hơn.

## 1. Mô hình rotation — ĐÍNH CHÍNH quan trọng
- Trong **burst đăng ký/attestation** (spawn tươi, hoặc sau wipe ov): slot16 **đổi gần
  như MỖI #19 message** (bắt được ~30 giá trị nonzero phân biệt trong ~60s). Producer
  chạy LIÊN TỤC ở pha này.
- Steady-state feed (đã đăng ký xong): dùng **zero-slot** (`00…0030`) — đã thấy trong
  log (`00000000000000000000000000000030`, tail 0x30='0').
- ⇒ Model "rotate chậm/ổn định" của các note trước là của *steady-state*; pha đăng ký
  thì per-message. Đây là cửa sổ producer hoạt động mạnh nhất.

## 2. slot16 KHÔNG có origin ổn định
- Cùng một giá trị slot16 (vd `b8f399c9…`) xuất hiện ở **nhiều địa chỉ heap khác nhau**
  (`0x7b89449fd0` rồi `0x7b8934a3d0`, …), địa chỉ tăng dần kiểu malloc tuần tự.
- ⇒ Producer malloc buffer mới mỗi message, ghi slot16 vào đó, rồi copy 16B vào #19.
- Hệ quả: **watchpoint-origin bất khả thi** (không có 1 địa chỉ cố định); các thử
  `_origin_watch.js`/`_origin2.js` đều ABORT_CHURN (value không đổi ở buffer đang watch,
  hoặc không latch được vì SLOT là mục tiêu di động — 0x172afc copy value N *trước* khi
  helper 0x9fd18 học value N).

## 3. Chuỗi gọi read/copy (khung ĐÁNG TIN, đã lọc rác)
Copy 16B slot16 vào #19 tại **metasec+0x172afc** (feed) / **metasec+0x15b5e4** (register),
chuỗi tĩnh trong metasec:
```
metasec+0xa0440   (copy caller — note47 §6 read-path)
metasec+0x9fe84
metasec+0xa101c
metasec+0x55950   (devirt-VM dispatcher — BỨC TƯỜNG note47)
```
- Site tĩnh thứ 2: **metasec+0x171954** (một số slot copy thẳng từ đây, backtrace nông).
- Tất cả offset < module.size (0x1ff800) ⇒ code tĩnh thật, KHÔNG phải bytecode ẩn.

## 4. CẢNH BÁO công cụ (đã mất thời gian vì cái này)
- `Thread.backtrace(ctx, FUZZY)` trên ARM64 **nhặt slot ngăn xếp cũ trỏ vào
  /memfd:frida-agent-64.so** (map ở `0x7a1e55d000–0x7a1fc2b000` trên máy này). Các khung
  `0x7a1exxxxx / 0x7a1fxxxxx` trong log CŨ là **rác của frida-agent, KHÔNG phải VM
  TikTok**. Lý thuyết "native VM handler dump được" là SAI. → Luôn lọc khung theo
  `/proc/pid/maps` trước khi tin.
- `Backtracer.ACCURATE` trên lib stripped + gọi ở site tần suất cao (0x15b5e4 ~90 lần)
  làm **script bị destroy/treo**. Chỉ FUZZY, và **dedupe theo value TRƯỚC khi backtrace**.
- `su 0 sh -c '...'` trên AVD này **chạy ở `/`** (nuốt tham số) → `find … -delete` đổ cả
  cây FS (45MB rác) và suýt nguy hiểm. Dùng dạng trực tiếp `su 0 <cmd> <args>`.

## 5. Key material sinh slot16 — runtime-derived (không tĩnh)
- Hai hằng 32-byte **cố định cả phiên**, luôn đi CẶP qua 0x15b5e4 (~89 lần/phiên):
  - `K1 = c02f250f86cc4f198d5706398d292a8b`
  - `K2 = 74169aba61affe7cba02e4a3b5198163`
  Mùi key+IV / 2 nửa device-key nạp vào hàm dẫn xuất slot16.
- Template init tĩnh-hoá lúc runtime: `782399bd facedead 3230313030343034`
  (`facedead` magic + ASCII "20100404"), nạp ở init path **metasec+0x145190/0x145790**
  (qua shadowhook + linker constructor).
- **Static grep libmetasec_ov.so:** K1, K2, full-template, "20100404" → **KHÔNG có
  trong binary** (chỉ `facedead` 4-byte trùng ngẫu nhiên @0x193074). ⇒ Tất cả
  runtime-derived từ attestation → **không có lối tắt tĩnh**.

## 6. Vì sao producer store vẫn không bắt được (giới hạn cấu trúc, không phải lỗi)
1. Origin heap tươi mỗi message ⇒ không watch được 1 địa chỉ.
2. Backtrace tại reader (0x172afc) không chạm producer (producer đã return trước copy).
3. Producer thực thi qua VM 0x55950 ⇒ lift = lift VM bytecode (đúng bức tường note47).

## 7. Hướng còn lại (cho vòng sau / human)
- **(Chiến lược — ưu tiên hỏi human):** Login/auth flow thật có CẦN nonzero slot16
  không, hay **zero-slot đã đủ**? Nếu zero-slot đủ cho login → no-phone login KHẢ THI
  NGAY với signer đã bank (không cần producer). Nếu cần đăng ký (nonzero handshake) →
  hoặc (a) đăng ký 1 lần trên AVD rồi tái dùng keystore ov, hoặc (b) lift producer.
- **(Kỹ thuật A — malloc-correlation):** hook allocator, gắn watchpoint WRITE lên
  buffer NGAY khi malloc trả về (trước khi producer ghi) → bắt đúng store + backtrace
  producer. Chi phí cao, cần lọc allocation 16–32B.
- **(Kỹ thuật B — lift VM 0x55950):** single-step/emulate dispatcher 0x55950 với input
  K1,K2 + counter để phục hồi F. Đây là sub-project lớn (đã đánh dấu bức tường ở nhiều note).
- **(Kỹ thuật C — truy nguồn K1,K2):** watch/hook nơi K1,K2 được SINH (không phải copy)
  → nếu K1,K2 = f(device_secret) tĩnh thì slot16 = keyed-PRF(K, nonce) có thể tái tạo.

## 8. Trạng thái bankable (KHÔNG mất dù chưa bắt producer)
- HW-watchpoint hoạt động trên AVD (Exynos thiếu) — note 48.
- Read-path xác nhận cross-device: 0xa0440 → 0x172afc, x2=16 — note 47 §6 khớp.
- Rotation model chính xác hoá (per-message trong burst đăng ký).
- Toạ độ producer: chuỗi tĩnh 0x9fe84/0xa0440/0xa101c + VM 0x55950 + site 0x171954;
  init template 0x145190; key K1/K2 (runtime).
- Offline #19 signer verified bit-exact (zero-slot + 11 nonzero tuples) — vẫn đứng.

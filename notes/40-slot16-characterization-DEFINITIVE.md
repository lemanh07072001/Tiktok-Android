# 40 — slot16 characterization DEFINITIVE (fork điểm quyết định)

Ngày: 2026-08-24. Tổng hợp từ replay unicorn + correlation live + dữ liệu cũ
(`_corr_data.json`, `slot16_newphone_verified.json`, `slot16_findings.md`).

## Điều ĐÃ CHỐT (bằng chứng, không phỏng đoán)

1. **X-Argus encoder + #19 = SM3(query‖slot16‖'0') : bit-exact offline.** (đã xong từ trước)

2. **slot16 = 0 cho gần như MỌI request** (feed, IM, upvote, subtitle, comment,
   actions…). Các request này **ĐÃ pure-offline** với encoder + công thức #19 hiện có.
   - Kiểm chứng: `slot16_newphone_verified.json` 30 record — 15 zero gồm
     `aweme_id=…`, `im_user_feature_names=…`, `item_ids=…`, `scene=…`, `user_type=…`.

3. **slot16 NONZERO chỉ ở request register/SDK-init**:
   `ssp_sdk_version=1&device_platform=…` và device-register heartbeat
   `device_platform=android&os=android&ssmix=a&_rticket=…`.
   (Cùng head `device_platform=…` có thể zero HOẶC nonzero tuỳ param sau → trigger là
   loại request register/heartbeat, không phải chỉ endpoint.)

4. **slot16 nonzero = F(PSK 32B, seed 4B)** — bằng chứng `_corr_data.json` 13 record:
   - `mat` (PSK 32B) **cố định** cả session: `c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163`
   - `seed` (4B) **đổi mỗi request**, slot16 đổi theo seed → slot16 phụ thuộc seed.
   - 13/13 slot16 **duy nhất** trong burst 59 giây.

5. **F KHÔNG phải hash/AES chuẩn.** Brute-force (findings §11.3-11.4 + harness):
   MD5/SHA256/SM3/HMAC của mọi tổ hợp (PSK, seed, rticket, k18) → FAIL.
   AES-ECB/CBC mọi key × mọi seed-block → FAIL. Ghi chú harness: "**modified AES**".

6. **seed = random per-request (client sinh).** Test offline: seed KHÔNG monotonic,
   KHÔNG = low-32(rticket), KHÔNG = md5(rticket)[:4]. → entropy tươi, do client tạo.

7. **slot16 được CACHE trên đĩa (.msp)** và tái dùng ~6.3h qua restart
   (findings §2.1: `0368525bbc8948577a33284cac9c660d` bền 6.3h, nhiều rticket khác nhau).
   → cùng 1 slot16 vừa bắt LIVE hôm nay = giá trị trong `slot16_obs.json` (session cũ)
   ⇒ cache/pool bền, không đổi mỗi lần.

## Ý nghĩa (reframe lớn)

- **Pure-offline signer cho request thường: ĐÃ XONG** (slot16=0).
- Nonzero slot16 chỉ cần khi muốn **tự forge request register/SDK-init offline**.
- Vì seed do CLIENT chọn (random) và gửi kèm để server verify ⇒ nếu **crack được F**,
  offline signer tự chọn seed → tự tính slot16 → nhét cả hai vào request. Không cần phone.
- ⇒ **Việc DUY NHẤT còn lại cho nonzero-offline: crack F (PSK×seed→slot16), 1 cipher "modified-AES".**

## Vì sao unicorn-replay chưa ra F

- Replay invocation 0x9fd74 (LR pos-1) = VM lắp-ráp report KHỔNG LỒ: chạy 36M block
  rồi **kẹt spin-wait** đọc `BASE+0x1fbaf8` (page chưa map, chờ nonzero) — external state.
- 0x9fd74 = report-assembly (output là con trỏ 0x78…), KHÔNG phải F. found={} khi so
  slot16 với buffer A/B/C (kể cả deref heap 64B). F là invocation/handler NHỎ khác.
- C (0x10ac84) trả 4-byte int → khả năng là bước **sinh seed**; A/B lắp report.

## 3 hướng cho nonzero (fork)

- **P1 — Crack F qua devirt/replay có mục tiêu:** tìm ĐÚNG handler tính F(PSK,seed)→slot16
  (nhỏ, self-contained), capture entry-state tại lúc PSK+seed cùng sống, replay unicorn
  đoạn NGẮN. Tránh VM khổng lồ. Nhiều-tuần, không chắc, nhưng là con đường "thuần tính".
- **P2 — A2-hybrid (đã proven):** hook SM3 nhẹ bắt slot16 live 1 lần/session; cache bền
  ~6.3h. Production-ready ngay. Không thuần-offline nhưng chỉ cần chạm phone hiếm.
- **P3 — Không cần nonzero:** nếu use-case chỉ ký request thường (feed/action/post) →
  đã pure-offline hoàn toàn, đóng task.

## ⚡ BREAKTHROUGH (cập nhật): slot16 = DETERMINISTIC (pure-offline KHẢ THI)

Thí nghiệm quyết định: **XÓA SẠCH cache .msp** (`find $OV -type f -delete`, 12→0 file)
rồi cold-start → slot16 **TÁI TẠO Y HỆT** pool cũ:
- `8ca46242…`=corr[1], `b6472e04…`=corr[7], `0b04cc91…`=corr[6], `3b4fa8c4…`=corr[9] (từ session cũ)
- ⇒ slot16 **KHÔNG phải cache trên đĩa**, mà **tính xác định từ PSK device-stable + index**.
- `46c03b52…` xuất hiện cho 2 query KHÁC nhau ⇒ slot16 phụ thuộc **index/counter nội bộ**
  (ratchet regfile[29]), KHÔNG phải full-query. seed(4B) = index đó.

**Hệ quả then chốt:** F là **hàm THUẦN xác định** F(PSK 32B, seed/index 4B) → slot16 16B,
tái lập qua cache-wipe + cross-session. ⇒ **pure-offline chắc chắn khả thi** nếu extract F.
Không có entropy tươi / server-gate. (đảo ngược nỗi lo "seed random không đoán được".)

## Black-box F: ĐÃ CẠN (mọi thứ fail trên 13 cặp)
MD5/SHA1/SHA256/SM3/HMAC mọi vị trí; AES-128/256 ECB/CBC/CTR mọi key×block;
hash-chain/ratchet SM3; SM3/AES-CTR keystream(PSK) 36k block; sandwich SM3. → F = cipher
tùy biến trong VM ("modified AES"). Phải LẤY TỪ VM, không đoán được.

## Định vị F: B(0x1384e8) là ứng viên mạnh nhất
Replay từng invocation (pipeline unicorn proven):
- **A (0x9fd74)** = report-assembly KHỔNG LỒ: 36M block, kẹt spin đọc con trỏ heap
  process (BASE+0x1fbaf8=ptr heap), traverse object → KHÔNG phải F. (`_replay_9fd74.txt`)
- **B (0x1384e8)** = NGẮN 2848 block, chạm **code SM3-area 0xa0fe8**, fault ở computed-jump
  (x16=0x9b374 VM-bias, target=bytes lệnh) vì thiếu page heap của bảng nhảy.
  → **B đang LÀM crypto** — F-candidate. Cần capture đủ heap/table của computed-jump.
  (`_replay_1384e8.txt`)
- **C (0x10ac84)** = trả 4-byte int → có thể sinh seed/index.

## Con đường còn lại (đã rõ)
1. Hoàn tất replay B: capture đủ page bảng-nhảy VM trong CÙNG frozen-invocation (light-BFS
   onEnter đang cap 500 page — cần nâng / target computed-jump table).
2. Hoặc Track-A devirt: reimplement dispatch VM deterministic (plan 1014 dòng) — chắc chắn
   nhưng multi-week. Determinism giúp verify bit-exact dễ.

## Dữ liệu chốt
`_corr_data.json` (13× PSK/seed/slot16) = tập vàng verify F offline (deterministic).
`_replay_9fd74.txt` (A=spin, không phải F) · `_replay_1384e8.txt` (B=crypto ngắn, F-candidate).
`msp_backup_2026-08-24/` = backup .msp gốc. Cache-wipe an toàn (app tự re-register).

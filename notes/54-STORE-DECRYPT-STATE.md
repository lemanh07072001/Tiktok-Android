# 54 — TRẠNG THÁI HỢP NHẤT: white-box decrypt .msp/.mss (Track C) — "còn phần nào"

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** 'ALL store = AES, chỉ thiếu key' **SAI cho 2/3 họ** — truth: **.msf3 = XXTEA** (key=MD5(keyname), filename=SHA1(keyname), core 0x152310, verified), **.msp = RC4/XOR-stream** = RC4(MD5(SHA1(keyname))) over [4Blen][zlib], **.mss = AES-256-ECB** KV-container; và device-secret đã capture **PRE-encrypt** @0x10bbd0 (plaintext dyn_seed/dyn_deviceid/kiid/rtk2_ms) ⇒ framing '1 unknown key' tan. Bản đồ offset AES subsystem vẫn đúng (phục vụ .mss + envelope).

**Ngày:** 2026-08-29 · **AI:** claude · **Nguồn:** `.ai/BOARD.md` (card 29a-29f), `STATUS.md`, oracle live phiên này.
**Mục đích:** 1 note duy nhất trả lời "còn phải làm gì" sau khi đọc lại toàn bộ .md. Thay cho việc phải lần lại 44 note + BOARD 1131 dòng.

---

## 0. Bản đồ giai đoạn (đã xong vs còn lại)

| Lớp | Trạng thái | Note/nguồn |
|-----|-----------|-----------|
| AUTH nền (signing, device_register, guard, guest, login→2135) | **SOLVED** | 01-PLAN Task1-5, 10/11/14/26/31 |
| x-argus / gorgon / khronos encoder | **SOLVED** | 29/30/36/37 |
| hash19 / pskcalhash | **SOLVED** | 33 |
| slot16 (nonce ký) | **SOLVED offline** — capture-once-reuse, DIFF-verified `46c03b52…`=GT#2 | 38-53, `ground-truth/endpoint_slot16_map.json` |
| **Store white-box (.msp/.mss/.msf3) decrypt** | **← FRONTIER, 1 ẩn số** | note này |

---

## 1. Thuật toán store = STANDARD AES — ĐÃ LIFT 100% (deliverable tĩnh)

Bẻ được card "no-cipher" cũ (grep trượt vì bảng lưu word-giãn-lane). Toàn bộ offset trong `bin/libmetasec_ov.so`:

- **key-schedule** `0x1591bc` — `Nr = keyBYTES/4 + 6`, arg `(AES_KEY*, userKey, keyBYTES)`; 8/8 call-site nhận `userKey` **runtime** (KHÔNG có key hằng trong .so).
- **sbox** 4-lane `0x196fbc / 0x1973bc / 0x1977bc / 0x197bbc` + **Rcon** `0x197fbc` (256B khớp tuyệt đối sbox chuẩn).
- **Td-decrypt** `0x198…/0x199…/0x19a…`; **block** decrypt `0x159618`/`0x15997c`, encrypt `0x159d1c`.
- **EVP dispatcher** `0x10d064`/`0x10db6c`; **jump-table** `0x18fa24`/`0x18fa2c` mode 0..3.
- **drivers**: mode1 `0x159d60`, mode2 `0x15a1dc`, mode3 `0x15a598` — mode3 zero counter tại `ctx+0x1f8` ⇒ **STREAM length-preserving** (khớp file KHÔNG chia hết 16).
- **layout**: `key = ctx->[8]->[8]`, `keyBYTES = ctx->[8]->[4]` (∈16/24/32), `IV = driver arg x3`; keysched(488B)@`ctx+0`, IV(16B)@`ctx+0x1e8`.
- **endian**: schedule lưu byteswap từng word 32-bit so với key thật truyền vào init.
- **filename = SHA1(keyname)** → hex, qua `0x10b13c`/`0x10b010` (SHA-1) + fmt `"%s/%s%s"` @`0x1909a0` + suffix `.msp_`/`.mss`/`.msf3_`.
- **getter** `0x1182d0` → switch mod-3 (3 loại store) → `0x10bbd0` chạy **OLLVM-VM** qua thunk `0x1119c8`; singleton `[0x1f2d70]` = TĨNH (rodata `0x192f`).
- **kho**: `/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov/`.

⇒ **Chỉ thiếu đúng 1 thứ: bytes KEY AES** (được sinh trong OLLVM-VM store-layer).

---

## 2. Ground-truth (bin thật, `huongB_devirt19/_msdump_live/`)

| file | size | head16 | keyname (SHA1 preimage) |
|------|------|--------|--------|
| `.msf3_5a78573b…` | 16B | `08134acf42c8f4127fd3a3e98b4b7956` | — |
| `.msp_092fde7a…` | 131B | `c3b27a642260175cb483156827c01af2` | `"sdi_v2"` |
| `.mss_9b8ed995…` | 262B | `75aa62270249304c2290151a22d4ca79` | `"mssdk_setting"` |

Test = **DIFF plaintext offline vs kho này** (không unit-test bịa).

---

## 3. Phiên này thêm gì (oracle spawn-gate, emulator UP)

- Spawn-gate (KHÔNG re-register, login còn) → hook AES-init + block core. Bắt **3 key phân biệt**:
  - req#1 `8252970d959b06db102e17d85c0ec1af` IV `4d207ea37a419f7d622f81c6a2f53594`
  - req#2 `b114249b7bed9d2691d70c60d69f9c4f`
  - **ứng viên store-key** (schedule form `de2dd7b8944251c0c82dbf8b9c75631d`) → byteswap ⇒ **`b8d72ddec05142948bbf2dc81d63759c`**
- **STOREHIT = 0**: ciphertext của 3 file store **không bao giờ** đi qua AES block core khi hook. ⇒ store chạy **stream (CTR/OFB/GCM)** *hoặc* decrypt xảy ra sau khi detach.
- Brute offline cả 3 key (mọi mode/IV thử) → **0 khớp** GT. ⇒ store-key ≠ 2 req-key; ứng viên `b8d72dde…` chưa verify.
- **Giả thuyết GCM (CHƯA test):** file = `[ciphertext][16B tag]`. Size khớp: 16=0+16, 131=115+16, 262=246+16. GCM dùng CTR nội bộ ⇒ giải thích STOREHIT=0. **Tag-verify = oracle định đoạt** (đúng key+nonce ⇔ tag pass).

---

## 4. CÒN LẠI — việc phải làm (đúng 1 ẩn số, 2 đường)

**Ẩn số:** bytes KEY AES store + (mode, nonce/IV). 2 khả năng loại trừ nhau:
- (a) key = H(keyname[+static]) ⇒ **forge offline được** (deliverable đầy đủ).
- (b) key = device/session secret ⇒ cần **1 lần oracle read** rồi reuse (như slot16).

**Đường A — oracle (nhanh, cần emulator UP):** hook `0x1591bc` onEnter đọc `(userKey,keyBYTES,IV)` ĐÚNG lúc mở 1 file store (arm bằng RDR `0xe2df0` như `_store_oracle.js`) → có key/nonce thật → DIFF offline. Read-only, KHÔNG re-register.
**Đường B — devirt VM store-layer** (`0x10bbd0`/`0x1182d0`): lift bytecode sinh key → chứng minh (a) hay (b). Nhiều ngày.
**Test dứt điểm GCM (làm ngay, offline):** với mỗi key ∈ {b8d72dde…, 2 req-key} × nonce ∈ {IV bắt được, 12B đầu, zero} → AES-GCM verify tag 16B cuối mỗi file. Pass = xong.

**Ưu tiên:** (1) GCM tag-verify offline (rẻ, quyết định ngay stream-mode) → nếu fail (2) đường A oracle đọc key khi emulator UP.

---

## 5. Công cụ canonical đã giữ (đừng xoá)
`huongB_devirt19/`: `_aes_oracle.js` `_store_oracle.js` `_blk_oracle.js`+`_blk_drive.py` `_crypto_oracle.js` `_sm3.js` (SM3 verified) `_compress.js`; ground-truth `_msdump_live/`. BOARD card 29a-29f + `.so` map giữ ở `.ai/BOARD.md`.

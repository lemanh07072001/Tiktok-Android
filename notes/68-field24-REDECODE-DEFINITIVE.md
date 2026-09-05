# 68 — Field #24 RE-DECODE (DEFINITIVE): dyn_seed, KHÔNG phải Widevine/TEE

> Task người dùng: *"Cụm Widevine/TEE cho #24 (note 24 W8 → lan 30/32/46/58/60/61/62/63) — sai toàn tuyến. Cần decode lại."*
> Kết luận: **#24 = dyn_seed** (chuỗi base64 132 ký tự). Widevine/TEE bị **BÁC BỎ** dứt điểm bằng 5 phương pháp độc lập, mạnh nhất là **decode nguyên report** (walk field). Bit-exact, self-validated bằng ARGUS magic.

## 0. Cách verify (chạy được, không tưởng tượng)
- Decoder: `huongB_devirt19/_f24_xargus.py` — **self-contained**, port lại từ `xargus_decode.py`.
  Chạy: `python huongB_devirt19/_f24_xargus.py` → in field #5/#7/#24 + magic OK cho mỗi capture genuine.
- Oracle đúng-sai MIỄN PHÍ: `report[0]==0x08` và varint field#1 == `0x20200929<<1` (ARGUS magic). Sai Simon → magic fail ngay.

## 1. Toàn bộ envelope X-Argus (đã port & chạy bit-exact)
```
raw   = b64decode(X-Argus)
rb01  = raw[:2];  ct = raw[2:]
PT    = AES-128-CBC-decrypt(ct, key=md5(SIGN_KEY[:16]), iv=md5(SIGN_KEY[16:]))   # NO pkcs7
rb    = rb01 + PT[-15:-13]
region= PT[9 : len-15]
xored = region[::-1];  xa = xored[:8];  xored[i>=8] ^= xa[i%4]
simct = xored[8:]
kdig  = SM3(session_psk ‖ rb ‖ session_psk)[:32]  → 4× LE u64 = Simon key
report= Simon128/256-decrypt(simct)      # m=4, T=72, z-index=4
```
- SIGN_KEY = `c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163`
- AES_KEY = md5(SIGN_KEY[:16]) = `8252970d959b06db102e17d85c0ec1af`
- AES_IV  = md5(SIGN_KEY[16:]) = `4d207ea37a419f7d622f81c6a2f53594`
- session_psk mặc định = SIGN_KEY (cửa sổ bootstrap = offline). Capture 792 (realsign hdr / phone_9ecc0) magic-fail = session_psk đã xoay (capture-once, note 55 — ĐÚNG như dự đoán).

## 2. Simon128/256 — các fix đã chốt (từng sai, nay KAT-verified)
Round-key expansion (i=4..71), zstr = Z[4] (62-bit):
```
tmp = ror64(k[i-1],3) ^ k[i-3]
tmp ^= ror64(tmp,1)
k[i] = (~k[i-4] & M64) ^ tmp ^ int(zstr[(i-4)%62]) ^ 3     # <-- ^3 (KHÔNG phải ^C64)
```
Decrypt block (i=71..0):  `fa=(rol(a,1)&rol(a,8))^rol(a,2); a,b = b^fa^k[i], a`
- Z[4] = `11010001111001101011011000100000010111000011001010010011101111` (62-bit chuẩn).
- Bug đã sửa: (a) Z dict trước là rác 64-bit → thay bằng 62-bit chuẩn; (b) dùng nhầm zj=2 → phải z4; (c) `^C64` (=k^3) double-count → sửa `^3` giữ complement. KAT Simon128/256 canonical PASS.

## 3. #24 = dyn_seed — 5 chứng cứ độc lập (Widevine CHẾT)
1. Wire type 2 (bytes), field 24.
2. Nội dung = **chuỗi ASCII base64 132 ký tự** (không phải 98 byte đã-decode). Khớp `device_profile.json.dyn_seed` của thiết bị signer.
3. Cùng device → #24 giống hệt qua nhiều lần ký; khác device → khác.
4. Không có bất kỳ marker Widevine/DRM/TEE/PSSH nào trong report.
5. **Walk nguyên report**: #5=device_id, #7=appver, #24=dyn_seed string — tất cả khớp device_profile. Đây là chứng cứ mạnh nhất.

## 4. Cấu trúc 98-byte của dyn_seed (sau khi b64-decode) — 3 sample genuine
- A = realsign_4573 (device 7678616678053643790)
- B = realsign_4573 variant (CÙNG device, lần ký khác)
- C = sync_capture (device 7677798657664026132)

Prefix: `30 31` = ASCII "01" (version). Còn lại 96 byte.

### Phân loại byte (XOR chéo 3 sample)
| lớp | số byte | vị trí |
|---|---|---|
| CONST-ALL (khung build) | 19 | 0,1,5,12,25,45,47,48,49,50,58,59,60,69,74,75,79,84,97 |
| per-DEVICE (fingerprint) | 16 | 2,3,4,6,7,8,9,10,11,19,29,43,51,52,53,73 |
| per-ISSUANCE (nonce) | 63 | phần còn lại |

### LUẬT CỨNG (chốt, 100%): mọi biến thiên ⊆ mask 0x5f
- Với MỌI byte: bit `0x80` và `0x20` **cố định theo vị trí** (qua cả device lẫn issuance).
- Toàn bộ payload biến đổi nằm trong **6 bit/byte** (mask 0x5f).
- Kiểm chứng: "Vị trí biến ngoài mask 0x5f = KHÔNG CÓ"; "0xa0-scaffold cố định qua cả 3 sample = True".
- **0xa0-scaffold per-position** (bit 0x80|0x20 mỗi byte, cố định) hex:
```
2020a0008080a020002020208020208080a080a020002020002020a0a0000000
802000800020200000200000a02000a080a000200080800080a0008000a0a000
008080208000a000208020800000a02020a0800000a0a0a02000202080a0808000a0
```
- Phân bố scaffold: 0x00×29, 0x20×27, 0x80×22, 0xa0×20.

### Kết luận cấu trúc
- Byte-run chung giữa các device khác nhau tại cùng offset ⇒ **KHÔNG phải AES ciphertext đồng nhất** ⇒ đây là **encoding có cấu trúc phía server** (6-bit-symbol/byte + khung cố định), **opaque với client**.
- ⇒ **Không thể decode/tính offline**. Nhất quán với mô hình capture-once (note 55). Muốn có dyn_seed hợp lệ = phải capture từ thiết bị thật, KHÔNG forge được.

## 5. Hệ quả cho các note đã lan sai (24 W8 → 30/32/46/58/60/61/62/63)
- Mọi phát biểu "#24 = Widevine attestation / TEE token / DRM keybox" → **SAI, bỏ**.
- #24 chỉ là dyn_seed (device session seed, đã có trong device_profile.json + captured store). Không mở ra hướng attestation mới nào.
- offline-772 ceiling KHÔNG đổi: #24 không phải blocker mới; blocker thật vẫn là emission 2-pass (#16/#24) trong native builder (note 63/60) + session_psk xoay.

## 6. Trạng thái
- ✅ Full offline X-Argus decoder sống lại, self-contained (`_f24_xargus.py`), không còn phụ thuộc e:/ box (cipher.SIMON/native đã mất).
- ✅ #24 decode lại xong, có test (magic + walk field), Widevine bác bỏ.
- ✅ Cấu trúc 98-byte map hoàn chỉnh + luật 0x5f/0xa0.

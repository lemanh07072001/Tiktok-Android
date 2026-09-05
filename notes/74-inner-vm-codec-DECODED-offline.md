# 74 — Lớp "VM-codec bên trong" GIẢI ĐƯỢC OFFLINE (đã TEST, không phải wall)

> User (2026-09-05): "lớp VM-codec bên trong biến report thật (#13/#14/#19/#20/#24…)
> thành 572B body opaque trong [0xEC][nonce][body] thuần offline — trước khi kết luận phải TEST."
> => Đã test quyết định. Kết luận cũ (notes/73 §8, notes/66: "chỉ còn lớp VM-codec = human decision")
> BỊ BÁC cho hướng DECODE/hiểu: codec này KHÔNG phải VM-wall, nó = codec Simon note-36/37 đã giải.

## 1. Giả thuyết đem test
"Body 572B opaque trong pt=[0xEC][~3B nonce][body]" là do một VM-codec riêng biệt chưa giải sinh ra.
CHỐNG giả thuyết: body chỉ là report protobuf đi qua **codec note-36/37 đã verify** (Simon128/256 z4 +
reverse-XOR + framing 9/15), key = SM3(SESSION_PSK ‖ rb ‖ SESSION_PSK)[:32], rb=rb01(2B ngoài AES)+rb23(pt[-15:-13]).

## 2. Cách test (thuần OFFLINE, không gửi gì lên server)
- Corpus: `cap.noindex/gettoken_crypt/crypt_20260905_151444.jsonl` — 94 event ENC_PT (pt bắt ngay
  đầu vào AES trên máy = ground-truth), giữ 92 pt (pt[0]=0xEC, len%16=0). Phân bố len {544:7,560:4,576:62,592:18,608:1}.
- Tool: `huongB_devirt19/_inner_test.py` (SM3 thuần-Python cross-check gmssl; Simon port verbatim từ
  `_f24_xargus.py` đã verify) + `_walk_mssdk.py` / `_walk_genuine.py` (liệt kê field, **varint-tag đúng chuẩn**).
- Anchor đúng-sai: end-to-end giải X-Argus THẬT `ground-truth/sync_capture.json` → byte-equal `_f24_xargus`.

## 3. KẾT QUẢ — codec giải được, TẤT CẢ field user hỏi đọc ra offline
- **74/92 pt → protobuf magic `08d2a4808204`** (field1=1077940818), combo trúng DUY NHẤT:
  framing 9/15 + reverse-XOR + psk=SIGN_KEY(c02f250f…) + z=4. 0 false-positive (~48-bit magic).
- Report parse SẠCH tới field #36 (device model "SM-G930S", "googleplay", "45.5.4"): key sai → rác sau block1,
  nên 30+ field mạch lạc = bằng chứng áp đảo cả report giải đúng, không chỉ block đầu.
- **★ BUG walker đã sửa (quan trọng):** parser đầu đọc tag 1-byte → desync ĐÚNG tại #16 (tag field≥16 = varint 2 byte,
  vd #16=`82 01`). Sửa đọc varint-tag đầy đủ → lộ toàn bộ field. "Report dừng ở #16" trước đây = **giả tạo do bug**, không phải giới hạn message.

### Field user hỏi — ĐỀU CÓ MẶT & ĐỌC ĐƯỢC (giá trị REDACTED, chỉ ghi luật/độ dài):
| Field | Dạng trong report | Khớp luật đã biết |
|---|---|---|
| #13 | 6 byte digest | = SM3(slot16)[0:6] |
| #14 | 6 byte digest | = SM3(Q)[0:6] |
| #16 | 25 byte (token/license b64-ish) | device token |
| #17 | varint | (= #12 timestamp-class) |
| #18 | 16 byte | kiid |
| #19 | **32 byte** SM3 đầy đủ | = SM3(Q‖slot16‖#20) |
| #20 | **"0"** | pskVersion="0" (khớp note-73/58 oracle 11/11) |
| #24 | **132-char b64** | = dyn_seed (khớp note-66 §7) |

(Full field set giải ra: 1,2,3,4,(5),6,7,8,9,10,12,13,14,15,16,17,18,19,20,21,23,24,25,26,28,29,30,31,32,33,34,35,36.)

## 4. 18 MISS = SESSION_PSK xoay (capture-once), KHÔNG phải codec-wall
- 18 pt MISS = đúng khối idx 82–99 (L=592×17 + L=608×1), LIỀN KỀ ở CUỐI capture.
- Không giải được bởi: SIGN_KEY, dyn_seed[0:32]/[32:64]/[64:96], × BE/LE, × z-variants, × fallback framing.
- Giả thuyết (mạnh, CHƯA capture xác nhận): đây là request SAU bootstrap → SESSION_PSK đã rotate (note-36).
  psk xoay là 1 giá trị session-bound capture-once, không phải codec khác. idx 5–81 (bootstrap window, psk=SIGN_KEY) giải hết.

## 5. Ý nghĩa & ranh giới (giữ nguyên human-gate)
- ĐÃ BÁC: "lớp trong VM-codec là wall chưa giải / cần human" — SAI cho hướng **decode/hiểu**. Codec = note-36/37,
  giờ chứng minh end-to-end trên x-argus 772 THẬT với đầy đủ field.
- KHÔNG đổi kết luận chiến lược: forge full-772 vẫn low-value + cyber-flag (notes 65/66). Giới hạn thật là
  **GIÁ TRỊ** device-state (slot16 nonzero, dyn_seed tươi, SESSION_PSK xoay = capture-once/online), KHÔNG phải codec.
- Chiều ENCODE (report→body) = nghịch đảo trực tiếp của decode đã verify (framing/reverse-XOR/Simon-ECB); outer AES
  đã giải 2 chiều (xargus_decode.py). Không thực thi forge — human decision.

## 6. Tái lập
```
cd huongB_devirt19
python _inner_test.py            # self-test + brute 92 pt (offline)
python _walk_genuine.py          # field-set report GENUINE (offline_inner_report.hex)
python _walk_mssdk.py            # field-set 3 report mssdk giải ra (rb01 đã biết)
```
Secrets (#24 dyn_seed / #18 kiid / #16 token / #19) chỉ nằm trong cap.noindex/ (git-ignored) — KHÔNG commit giá trị.

## 7. 18 MISS — offline PSK-derivation ĐÃ TEST & VÉT CẠN (0/51), review PASS
**Task user "1" (đóng nốt 18 MISS).** Sweep `huongB_devirt19/_psk_sweep.py` → kết quả
`_psk_sweep_result.txt`. THUẦN OFFLINE, không gửi gì, không in secret.

**Harness (đã review kỹ — không có bug ngụy tạo 0-HIT):**
- CONTROL 1 (dương): SIGN_KEY × pt HIT idx5 → **HIT** rb01=ba25, magic OK — chạy ĐÚNG pipeline
  `psk_job` (make_simct→digest_sweep→fast_key_expansion→fast_dec_block→TGT48→full_decode). Fast-path bắt HIT khi có.
- CONTROL 2: brute SIGN_KEY trên 19 pt band-MISS → chỉ giải 1 (idx81) ⇒ **18 MISS thật** = idx82–99 (L592/608).
- ctrl:SIGN_KEY trong sweep (âm): SIGN_KEY × PT0 idx82 → MISS ⇒ pipeline báo MISS đúng khi key khác.
- Self-check: `digest_sweep==sm3` (13 độ dài 19..132), walker field≥16, hmac, simon-fast==ref — **ALL PASS**.
  ⇒ đường `digest_sweep` (biến-thể độ-dài của SM3 prefix-state) chính xác trong đúng dạng kết hợp dùng để brute.

**Không gian giả thuyết đã thử (51 candidate, PT0=idx82, mỗi cái brute trọn 65536 rb01):**
- note-36:92 `f(license L=SIGN_KEY + keva triplet s/q/t)` với f ∈ {concat-raw, SM3, XOR, HMAC-SM3}, mọi hoán vị + vị trí L.
- Cơ hội: raw/SM3 của rtk2_ms, kiid, dyn_deviceid, dyn_seed(ascii+b64d), b2a9d40c(+[:32]).
- **Kết quả: 51 tried, 0 HIT.** Không candidate nào giải PT0.

**Kết luận (chốt, có test):** derivation OFFLINE bằng **KDF rẻ-liệt-kê từ vật liệu đang có** cho SESSION_PSK xoay
= **VÉT CẠN, thất bại**. KHÔNG đồng nghĩa "offline bất khả tuyệt đối": còn 2 đường CHƯA thử (đắt):
  (a) KDF lặp/chuẩn (PBKDF2/HKDF-SM3/iterated) hoặc triplet cần biến đổi trước (tên keva đảo ngược: sdi/ecneuq/semithc);
  (b) derivation NẰM TRONG OLLVM-VM (đã black-box-fail 350 combo cho .msp key anh em — xem `mem:msp-cipher-xorstream-vm-gated`).
Đường RẺ & CHẮC còn lại để đóng 18 MISS = **1 lần capture SESSION_PSK xoay** (live, sau LOGIN fido2/passport) —
**human-gate** (thiết bị thật). Không thực hiện tự động.

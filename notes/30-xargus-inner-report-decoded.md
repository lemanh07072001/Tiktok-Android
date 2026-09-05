# 30 — X-Argus INNER report DECODED (plaintext protobuf) — dump live không cần key (2026-08-18)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** addendum T7b 'field #24 = Widevine MediaDrm hardware attestation' + row bảng 'Widevine MediaDrm TEE' **SAI** — #24 = **dyn_seed**: blob opaque server-issued từ 'mssdk/ms/get_seed', trên wire = chuỗi base64 132-char (98B decode, prefix 30 31 = '01'), không phải nested protobuf, không liên quan TEE/DUID (note 64 decisive experiment + note 66 §7 live byte-decode; MediaDrm DUID 44-char chỉ là request-side signal). Bảng 35-field + data genuine #24='MDGnGpX…' (132-char, decode → 0x3031) vẫn là ground-truth đúng.


> Đột phá: bắt được **plaintext INNER report** của X-Argus TRỰC TIẾP tại `memcpy` (trước khi mã hoá),
> KHÔNG cần reverse AES key/IV. Parse ra protobuf → **bảng field byte-offset thật** + phân loại
> static/dynamic từ **18 report live** (app official 45.7.3, phone ce031603). Bổ sung note 23/24/29.

## Bối cảnh — vì sao đi đường này
- Static localize điểm AES **bất khả**: scan toàn `.text` = **0 AESE/AESMC, 0 sbox chuẩn, 0 Te/rcon**
  (cipher obfuscate hằng số) + capstone **desync** trong hàm ký `0x9ecc0` (aligned-disasm 42/2048 insn)
  ⇒ mọi "BLR offset" scan tĩnh là GIẢ, hook vào = crash app (đã tái hiện 2 lần).
- ⇒ Chuyển **dynamic**: không tìm AES, mà bắt **plaintext report** ngay trước khi nó vào cipher.

## Phương pháp (proven, an toàn)
1. `libmetasec_ov.so` 45.7.3, hàm ký `0x9ecc0` (url,cookie)→char*, fire trên MỌI request thật.
   X-Argus genuine = **792 b64 = 594 raw = prefix2(2B) + 592B AES-CBC** (592/16 = 37 block chẵn).
   `prefix2` **đổi mỗi request** (`d9c4/d379/d862/0aa3/fc29`) → seed per-request, KHÔNG magic cố định.
2. Stalker `onCallSummary` trên 1 sign → callee thật: top = PLT `malloc/free/memcpy` (0x30610/0x30590/0x303d0)
   — churn `xstring` (khớp note 23 F2). Cipher không lộ ở đây (obfuscated), nên KHÔNG hook AES.
3. **Hook `libc memcpy`** (PLT stub không hook được → hook export thật), gate bằng cờ `SG` (bật trong `0x9ecc0`),
   lọc `len` + buffer bắt đầu `08 d2..` (protobuf field1 varint). → **bắt plaintext report 640B** trước mã hoá.
   Tool: capture ad-hoc (memcpy hook + protobuf parser). Artifact: `ground-truth/xargus_inner_report_45.7.3.bin`,
   `xargus_inner_reports_18x.json` (18 mẫu).

## 🎯 BẢNG FIELD — INNER report = **protobuf** (~640B plaintext → AES-CBC → 592B)
S = static (giống hệt 18 sign) · D = dynamic (đổi mỗi request). `#distinct` trên 18 mẫu.

| # field | type | S/D | distinct | Ý nghĩa (suy từ giá trị) | mẫu |
|---|---|---|---|---|---|
| #1 | varint | S | 1 | seq/const | 1077940818 |
| #2 | varint | S | 1 | proto/format ver | 2 |
| #3 | varint | **D** | 17 | timestamp/counter mịn | 1368569758 |
| #4 | bytes4 | S | 1 | **aid** | "1233" |
| #5 | bytes19 | S | 1 | **device_id** | "7674923887225882119" |
| #6 | bytes10 | S | 1 | id phụ | "2142840551" |
| #7 | bytes6 | S | 1 | **app_ver** | "45.7.3" |
| #8 | bytes20 | S | 1 | **metasec SDK ver** | "v05.02.07-ov-android" |
| #9 | varint | S | 1 | ? | 168037952 |
| #10 | bytes8 | S | 1 | flags | 0001000000000000 |
| #12 | varint | **D** | 7 | khronos/ts thô (đổi mỗi vài giây) | 3574048118 |
| #13 | bytes6 | **D** | 4 | nonce/MAC-like | 8082efd0a748 |
| #14 | bytes6 | **D** | 18 | nonce per-request | e86687056493 |
| #15 | bytes17 | **D** | 18 | nested (per-req state) | 08ba0410042004281e30… |
| #16 | bytes25 | S | 1 | **device_token** (server-issued, base64) | "AD5UM15cwOSidxg-rNCstrm8Q" |
| #17 | varint | **D** | 7 | khronos/ts (= #12) | 3574048118 |
| #18 | bytes16 | S | 1 | uuid16 device-bound | 3ce2766b40195144a93b6c0ccc3e1307 |
| #19 | bytes32 | **D** | 18 | **req_hash/sig per-request** (sha256-len) | 5524c091fa6efee7… |
| #20 | bytes1 | S | 1 | flag | 00 |
| #21 | varint | S | 1 | ? | 738 |
| #23 | bytes30 | S | 1 | nested **{model "SM-G930F", channel "googleplay", ts}** | 0a08534d2d4739333046… |
| **#24** | **bytes132** | **S** | **1** | **🎯 ATTESTATION/device-state BLOB (base64, ~99B) — STATIC, device-bound, cache 1 lần** | "MDGnGpXSpHsBJj8xg2wyzoO2…" |
| #25 | varint | S | 1 | ? | 8 |
| #26 | bytes16 | **D** | 18 | nested per-req | 080c120c7b94b7fc… |
| #26 | bytes23 | **D** | 18 | nested per-req (repeated) | 08e00f12126ccf58… |
| #27 | varint | S | 1 | ts base | 3574046446 |
| #28 | varint | S | 1 | ? | 1206 |
| #29 | varint | S | 1 | ? | 33553938 |
| #30 | varint | S | 1 | ? | 6 |
| #31 | varint | **D** | 18 | per-req val | 3332298597 |
| #32 | bytes24 | S | 1 | blob device-bound | 65d4a4323c59fd1a… |
| #33 | varint | S | 1 | ? | 4 |
| #34/#35/#36 | varint | **D** | 18 | **signature parts (per-request)** | 7491154246849273842 … |

## 🎯 KẾT LUẬN — gap offline↔phone map chính xác về field
- **Phần STATIC device-identity** offline THỪA SỨC dựng: aid/device_id/app_ver/SDK/model/channel (#4/5/7/8/23).
- **Phần offline THIẾU = device-state thu thập trên máy thật, đặc biệt:**
  - **#24 (132B, STATIC) = attestation/device-state blob** — mảnh to nhất, device-bound, metasec tính bằng
    collect-thread/get_seed rồi CACHE. Offline (unidbg no-GMS, collect-thread crash) không tạo được → report ngắn.
  - **#16 device_token** (server-issued), **#18 uuid16**, **#32 blob24** — device-bound state.
  - **#19 req_hash + #34-36 sig** (per-request) — ký TRÊN device-state; offline có key vẫn sai vì input (state) thiếu.
- Khớp toàn bộ note 23/24/29: gap KHÔNG do version/length-vô-cớ mà do **device-state (#24 & bạn bè) chỉ dựng được
  trên device thật**. Đây là bản-đồ-field cụ thể cho kết luận "collect-thread wall".
- ⇒ Muốn x-argus offline = genuine: phải tái tạo **#24 attestation blob** (+ #16/#18/#32). #24 STATIC ⇒ **extract 1 lần
  từ phone → feed offline** khả thi (đúng mô hình note 24 W17 "1-phone-mint → ∞-offline"); regenerate #24 thuần offline = chưa.

>
> **ĐÍNH CHÍNH/BỔ SUNG (2026-08-18, note 32 T7b):** field **#24 (132B attestation)** = **Widevine MediaDrm hardware attestation**.
> Đo trong unidbg: collect-thread gọi `new java.util.UUID(0xedef8ba979d64ace,0xa3c827dcd51d21ed)` = **Widevine UUID
> `edef8ba9-79d6-4ace-a3c8-27dcd51d21ed`** rồi `new android/media/MediaDrm(UUID)` → truy `getPropertyByteArray`/DRM
> device-id (TEE-backed). ⇒ #24 device-static, KHÔNG regenerate offline được (unidbg không có DRM/TEE hardware).
> #18/#19/#32 chết cùng khi MediaDrm fail. Đây là bản chất 'collect-thread wall' — cụ thể = Widevine DRM.

## Ghi chú
- KHÔNG cần AES key: bắt plaintext tại `memcpy` trước cipher. (Nếu vẫn muốn key: cipher obfuscate, không AESE/sbox → RE sâu.)
- Anti-frida: app official ẩn khỏi `enumerate_processes` → **attach BẰNG PID**. Shamiko+DenyList che root → launch mới sống với frida-server.
- Cảnh giác: hook 14 offset mid-fn (từ scan tĩnh desync) = CRASH. Chỉ hook function-entry thật (Stalker cho) hoặc export libc.

---

## 🔬 DIFF THỰC NGHIỆM: offline harness vs genuine phone (2026-08-23)

Bắt plaintext inner report OFFLINE tại libc `memcpy` (hook `SIGN_REPORT` trong Harness.java,
filter `08 d2 a4`, đúng như phone `psk_crypto_probe.py`). Artifact: `huongB_devirt19/offline_inner_report.hex`.

**Offline = 320B · Genuine = ~640B ⇒ offline thiếu ĐÚNG một nửa (đúng "report ngắn" note này dự đoán).**

### Có offline + ĐÚNG (khớp genuine)
`#1 #2 #3 #9 #10 #12..#15 #20 #21 #25 #28..#31 #33 #34..#36` + **`#32` blob24 = `65d4a4323c59fd1a…` KHỚP genuine**.

### Có offline nhưng SAI GIÁ TRỊ (phụ thuộc state nạp vào — sửa được bằng feed state phone thật)
| # | offline | genuine | sửa |
|---|---|---|---|
| #7 app_ver | `45.0.3` | `45.7.3` | đổi config/license harness |
| #16 device_token | `AqYwWbSgn41f7kiZdtxWZHpzi` | `AD5UM15cwOSidxg-rNCstrm8Q` | feed device_token thật (server-issued) |
| #23 model | `Nexus 5X`/googleplay | `SM-G930F`/googleplay | profile thiết bị (đã có fakedev/MS_SPOOF) |

### THIẾU HẲN offline (đây là "thiếu chỗ nào")
| # | field | bản chất | gỡ được? |
|---|---|---|---|
| **#5** device_id | identity | **fixable** — chỉ cần feed device_id vào state |
| **#18** uuid16 | device-bound | ❌ chết cùng MediaDrm |
| **#19** req_hash | per-req sig (slot16) | ❌ slot16 wall (đã chứng minh bất khả offline) |
| **#24** attestation 132B | **Widevine MediaDrm TEE** | ❌ unidbg không có DRM/TEE |
| #26 nested / #27 ts | collateral #24 | ↑ theo #24 |

**KẾT: 3 tường cứng = `#18 / #19 / #24` (Widevine TEE + slot16). 3 field còn lại (`#5/#26/#27`) sửa được bằng feed state.
`#7/#16/#23` chỉ sai giá trị, không thiếu. ⇒ x-argus offline = genuine đòi: (a) mint `#24` 1 lần trên phone rồi feed
(mô hình W17 "1-phone-mint → ∞-offline"), (b) feed device_id/device_token thật, (c) slot16 capture per-session.**

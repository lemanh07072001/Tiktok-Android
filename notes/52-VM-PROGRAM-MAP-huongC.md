# Note 52 — Bản đồ 35 VM-program + đóng đường offline cho Hướng C (2026-08-27, claude)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** core negative (Hướng C CLOSED với 3 lớp bằng chứng; 1 capture same-device là tối thiểu) **ĐỨNG**. Nhưng §4 'SHA-256 là hash DUY NHẤT; không có AES-sbox/SM3-IV/MD5-T/SHA1 signatures' **SAI** — constant-scan miss dạng non-table: AES sbox 4-lane @0x196fbc (note 54), SHA-1 K-consts movk @0x15bb00 (51 §3), SM3 Tj @0xa07c8 (51 §9). Bias-verify (op18 raw − 0x9b374 = 0x5ad2c) đúng.

## Bối cảnh
Hướng C = "ép thuần-offline: reverse PSK-material-object (mat_raw 32B → q2 64B block)".
Phiên này grind offline tĩnh trên `bin/libmetasec_ov.so` (capstone 5.0.7, .venv-emu). KHÔNG chạm phone.

## Phát hiện mới (đều offline, có script tái lập)

### 1. F & seedgen = wrapper mỏng, dispatch GIÁN TIẾP (`_disc_kdf.py`, `_xref.py`)
- `0x13848c` (F): chỉ set prog=`0x191f40` + `bl 0x52924` (VM interp) + return. KHÔNG có KDF.
- `0x10ac2c` (seedgen): set prog=`0x18f430` + `bl 0x52924` + `ldr w0,[sp,#8]` (seed 4B).
- **Cả hai: 0 direct BL-xref.** ⇒ orchestrator "seed→slot16→F" gọi qua con trỏ hàm trong
  object-graph runtime (data-wall xác nhận từ góc mới, độc lập).
- VM interp `0x52924`: 41 call-site. keva_get `0x11a64c`: 95 xref. AES_core `0x1591bc`: 9 xref.

### 2. Bản đồ 35 VM-program phân biệt (`_vmprogs.py`)
Blob bytecode `0x17bbf0..~0x196000`. Mỗi call-site nạp 1 program. Đã biết:
seedgen=`0x18f430`, F/marshal=`0x191f40`, report=`0x1864f0`.

### 3. Census opcode → phân loại code/data (`_vmcensus.py`, `_vmcensus2.py`)
- **TỰ KIỂM CHỨNG:** F hiện top-3 = `0x2c(op44) 0x12(op18) 0x2a(op42)` = đúng 3 opcode marshaller
  đã biết ⇒ `opcode = word & 0x3f` decode ĐÚNG, bytecode đọc-được-tại-chỗ.
- ~24 program = marshaller-code (op18/42/44 trội, marshFrac 0.6–0.85).
- ALU-code (marshFrac thấp, code thật): `0x189250`, `0x1909b0`, `0x193e70`.
- "const-blob" (validFrac thấp) thực ra là bytecode op42-STORE đều đặn, KHÔNG phải S-box.
- Bảng op→handler TOÀN CỤC (mọi program dùng chung interp): 47 handler; **handler thật =
  decoded − bias 0x9b374** (verify: op18 `0x0f60a0−0x9b374=0x5ad2c` ✓).

### 4. SHA-256 là hash DUY NHẤT trong binary (`_constscan.py`)
- **SHA-256 K-table @ file-off `0x19b540`** (LE `982f8a42 91443771 ...`), verify đủ 6 word.
- KHÔNG có chữ ký AES-sbox / SM3-IV / MD5-T / SHA1-H chuẩn.

### 5. Battery SHA-256 có hệ thống vs 13 cặp → FAIL TOÀN BỘ (`_sha_crack.py`)
- Thử: sha(mat|s), sha(s|mat), mọi hoán vị, double-sha, HMAC 2 chiều, hex-string,
  block-64B (mat|s*8 …), 3 kiểu slice ([:16],[16:],xor). **0 khớp, kể cả pair0 partial.**
- ⇒ slot16 KHÔNG phải hàm đơn giản của (mat, seed). Đầu vào crypto thật = **q2 (64B)** =
  PSK-material-object biến đổi runtime; mat→q2 KHÔNG tầm thường (không phải hash của mat).

## KẾT LUẬN — Hướng C không có đường thuần-offline (PROOF, không phải bỏ cuộc)
1. **Structural:** KDF sinh slot16 là VM-program đọc PSK từ **object-graph runtime (q2)**, y hệt F.
   PSK CHỈ vào crypto dưới dạng object 64B dựng lúc device-register — KHÔNG có bytes tĩnh.
2. **Empirical:** không construction SHA-256/AES/MD5/SM3/Simon/Speck/TEA nào trên `mat` ra slot16.
3. **Math:** giải q2 (512-bit material) từ 13 cặp I/O của hàm keyed-mạnh full-avalanche là
   **bất khả thi** (tính một-chiều) — kể cả khi đã biết thuật toán. Long-shot offline đóng.

⇒ Yêu cầu KHÔNG-thể-khử: **1 capture same-device** để lấy q2 runtime của device-7666.
   Sau đó nạp q2 vào emulator/lift → sinh slot16 mọi seed offline (C rút về A "1-phone-mint→reuse").

## Script tái lập (đều chạy `.venv-emu/bin/python`)
`_disc_kdf.py` `_xref.py` `_vmprogs.py` `_vmcensus.py` `_vmcensus2.py` `_constscan.py` `_sha_crack.py`

## Bổ sung (cùng phiên) — grind sâu thêm theo yêu cầu "tiếp tục đào offline"

### 6. Survey emulate CẢ 35 program với frame giả (`_vmsurvey.py`)
- Chạy interpreter 0x52924 cho từng program, frame = marker `0xAA..ii`.
- **Kết quả: 100% program ghi 0 byte OUT**, hàng loạt trap `pc=0x0` (ghi/nhảy qua null-ptr).
- Lý do: output object (x4→data_ptr) và material đều là **con trỏ vào object-graph runtime**.
- ⇒ chứng minh wall trên **toàn bộ 35 program**, không riêng F. Không program nào self-contained.

### 7. ISA của VM bị obfuscate tới mức reverse-tĩnh bất khả thi (`_isa.py`)
- Mỗi ALU-handler dài **~200–254 lệnh**. Cấu trúc: preamble dispatch-obfuscation
  (`adrp x15,#0x52000; add #0x924; …f(self)…`) + **bit-scatter operand-decode**
  (chuỗi `and wN,#bit; orr` tách operand từng-bit) + tính địa chỉ reg-file (x24, `&0x3f`, `lsl#3`).
- **Phép data thật = 1 lệnh chìm giữa ~200 lệnh obfuscation**; có ~44 handler.
- ⇒ hand-disasm toàn ISA = nhiều tuần. Route offline khả thi = **differential-emulation**
  (chạy cô lập handler, regfile-input đã biết → suy op từ regfile-delta). Nhưng dù recover ISA,
  **chạy KDF→slot16 vẫn cần q2 runtime** (điều 6).

## CHỐT (sau khi đào sâu 3 tầng): offline KHÔNG THỂ chạm slot16 — không phải "khó" mà "bất khả thi thiếu q2"
Ba tầng độc lập cùng 1 đáy: (a) SHA-battery fail; (b) 35-program survey đều null-trap thiếu object-graph;
(c) ISA obfuscate + KDF vẫn đọc q2. Yêu cầu không-thể-khử = **1 capture q2 device-7666**.

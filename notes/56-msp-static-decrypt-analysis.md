# 56 — .msp static decrypt CRACKED: RC4( MD5(SHA1(keyname)) ) — pure-python (see §9)

**Ngày:** 2026-09-01 · **AI:** claude (solo) · **Task:** ".msp/.mss fully-static decryptor" (verify vs `cap.noindex/gt_live/.msp_*`)
**Nguồn:** ground-truth thật `cap.noindex/gt_live/` + plaintext đã extract `cap.noindex/msstate_.../device_secret_plaintext/`.

---

## 0. Kết luận 1 dòng (CẬP NHẬT §8, 2026-09-02)
Cipher lớp cuối của `.msp/.mss` = **XOR-stream length-preserving** (crypt `0x10bbd0`: crypt(X)=X^ks, ks=f(key)) trên `zlib(json, level1)`. VM (thunk `0x1119c8`) **emulate ĐÚNG** sau khi chạy `.init_array` (§8) — keymat `0x10b010`=**MD5(keyname)**, `0x10b13c`=**SHA1(keyname)**; crypt đọc CHỈ static memory ⇒ primitive static-pure. **Còn thiếu ĐÚNG key** app truyền (≠ MD5/SHA1(keyname) & ≠ device-secret; ~120 ứng viên miss) — key do getter `0x1182d0` dựng, capture bị chặn bởi logger singleton lazy `[0x1fbaf8]`. NGHIÊNG static (chưa dứt điểm). `.msf3` (XXTEA) tĩnh-thuần 100%. Plaintext `.msp` đã có qua capture-once. **§3-6 dưới là phân tích cũ (09-01, giả thuyết "key VM-gated không emulate được") — §8 ĐÍNH CHÍNH: VM emulate được, keymat=MD5 (không phải SHA1-20B), gap thật = data-flow key trong getter.**

## 1. Cặp ground-truth (đối chiếu, KHÔNG bịa)
| file | size | keyname (SHA1 khớp filename) | plaintext (đã extract) | json len |
|------|------|------------------------------|------------------------|----------|
| `.msp_092fde7a…` | 272B | `sdi_v2` | `69c65eb5….json` (counters `1233-0-1-*`) | 469B |
| `.msp_589c2233…` | 375B | (device-secret store) | `8fd6b14a….json` (dyn_seed,kiid,rtk2_ms) | 494B |
| `.mss_9b8ed99…` | 630B | `mssdk_setting` | (chưa capture) | — |

SHA1("sdi_v2")=092fde7a…, SHA1("mssdk_setting")=9b8ed99… → **filename = SHA1(keyname)** xác nhận lại.

## 2. Cấu trúc cipher — 3 bằng chứng ĐỘC LẬP
1. **Length-preserving:** `len(zlib(json, level=1)) == len(file)` CHÍNH XÁC cho cả hai store (272==272, 375==375). ⇒ không có nonce/tag/IV nhét trong file; cipher là stream.
2. **XOR position-fixed / keystream ổn định theo store:** so head16 của 2 lần capture khác thời điểm cho `.msp_092` (note-54 cũ 131B vs gt_live 272B): **bytes[2..5]=`7a642260` GIỐNG HỆT**. Với trung gian `[4B len][78 01]` ⇒ pt[2..5]=`00 00 78 01` cho mọi capture ⇒ ks vị-trí-cố-định. (Cross-check: ct_092[0..1]^ct_589[0..1]=`b8d0`≠`0000` ⇒ keystream KHÔNG chia sẻ giữa store ⇒ key per-keyname.)
3. **Khớp static-lift note-54:** mode3 driver `0x15a598` zero counter tại `ctx+0x1f8` = STREAM length-preserving; giải thích STOREHIT=0 (ct không qua AES block-mode).

Trung gian (pre-encrypt, bắt ở 0x10bbd0 phiên trước) = `[4B LE decompressed_len][zlib magic 78 01]` → `zlib.decompress` → json.

## 3. Black-box known-plaintext attack — ÂM TÍNH (dữ liệu loại trừ)
Oracle = "XOR keystream rồi `zlib.decompress` khớp json đã biết". Đã thử ~**350 tổ hợp**, 0 trúng:
- XOR lặp: MD5/SHA1/SHA256(keyname), keyname, const `c1167e09a3f577f6b2056019a5e27ce0`.
- Hash-CTR/MGF1: H(seed‖ctr) & H(ctr‖seed), seed∈{name, md5/sha1(name), const, dev-key}, H∈{md5,sha1,sha256}, ctr∈{<I,>I,<Q,>Q}.
- HMAC-SHA1/MD5/SHA256(seed, ctr).
- RC4: key∈{sha1/md5(name), name, filename-hex/bytes, const}, drop∈{0,256,768,1024,3072}.
- AES CTR/OFB/CFB: key∈{const, K1..K7/K32 nhúng .so, 3 dev-key đã bắt `8252970d`/`b114249b`/`b8d72dde`, md5/sha1/sha256(name), filename}, IV∈{zero, one, devIV `4d207ea3…`, md5/sha1(name), filename, const}.

⇒ key KHÔNG phải hàm phẳng của keyname/hằng-số/khóa-request ⇒ **key sinh trong VM** (khớp Ghidra: `0x10bbd0`, `0x10b010` đều `blr [0x111000+0x9c8]=0x1119c8` + `br x14` CFF + opaque `madd`/reciprocal `0x4925/0x2492`).

## 4. Đường crypt (Ghidra/disasm)
- Getter read-record `0x1182e0` → dispatch **mod-3** (`ldrsw x8,[x20+4]` * recip `0x55555556`): kind0→`0x10bbd0` (device-secret), kind1→`0x10c158`, kind2→`0x10dce0` (XXTEA/.msf3).
- Caller kind0 `0x1184a4`: `0x10bbd0(x0=out, x1=in@sp+0x40, x8=x20=&keymat@fp-0x48)`. keymat = `0x10b010(keyname_struct{len@4,data@8}, mode=1)` → digest **20B (SHA1-len)** — nhưng 0x10b010 chạy qua VM (không phải SHA1 chuẩn: RC4/AES với SHA1(name) đã trượt ở §3).
- Cả `0x10bbd0` và `0x10b010` = OLLVM-CFF-flattened, đọc `tpidr_el0` canary, dispatch qua VM thunk `0x1119c8`.

## 5. Emulator offline (Unicorn) — TIẾN BỘ vs note-39
Deliverable: `huongB_devirt19/_msp_emu3.py` (+ `_plt_map.json` 165 import, `_aes_pure.py`).
- **Chạy `.init_array` 147/147 ctor SẠCH** trước worker (loader-faithful) — đây là mấu chốt: bản `_msp_emu.py` cũ bỏ qua init + dùng địa chỉ PLT stub SAI (đoán) nên spin ngay.
- PLT resolve ĐÚNG từ `.rela.plt`+`.dynsym` (layout .plt: header 32B, entry 16B); stub đầy đủ allocator/mem/str/pthread/once/guard(+memcmp/strtol).
- **VM thunk `0x1119c8` emulate tới `ret` KHÔNG diverge** (vượt "wall" note-39 — divergence cũ do thiếu init_array/ctor dựng dispatch-table).
- **Còn kẹt (last-mile):**
  - (a) Worker C++ `0x12f290` spin ở singleton **lazy** `[.bss 0x1fbaf8]` — KHÔNG do static ctor dựng (watch ghi init: 0 write vào 0x1fbaf8); là runtime/logging singleton dựng lúc app chạy. Stub dummy-object → CPU exception (obj thực sự bị dùng).
  - (b) Emulate thẳng `0x10b010`/`0x10bbd0` tới RET nhưng **output std::string chưa đúng** (ABI sret x8 + globals VM đọc zero-page ⇒ nghi path VM degenerate hoặc cần device/session global).

## 6. Việc còn lại (well-defined, cho phiên sau)
Muốn decrypt `.msp` tĩnh-offline, chọn 1:
- **B1 — hoàn thiện emulate 0x10bbd0 trực tiếp:** dựng đúng ABI (x0=out std::string, x1=in std::string chứa file bytes, x8=keymat 20B), + trace read → map các global VM đọc phải (nếu chỉ .so-static ⇒ THẮNG tĩnh-thuần; nếu chạm device/session bss ⇒ chứng minh device-gated). Tool sẵn: `_msp_emu3.py` (thêm setup args + read-trace như `_slot16verify.py`).
- **B2 — emulate READ entry 0x1182e0(keyname)** với fopen/fread stub trả file bytes (tránh wrapper 0x12f290 spin), để lib tự dispatch→0x10bbd0.
- **B3 — devirt CFF thunk 0x1119c8** (nặng, nhiều ngày).

**Không chặn deliverable tổng:** plaintext `.msp/.mss` đã có qua capture-once (`device_secret_plaintext/`), và `.msf3` decrypt tĩnh-thuần đã xong. `.msp` static-decrypt = tối ưu hoá, không phải nguyên liệu thiếu.

## 7. Artefacts phiên này
`huongB_devirt19/_msp_emu3.py` (emulator init_array+PLT đúng), `_plt_map.json`, `_aes_pure.py`. Env: venv `~/.re-venv` (unicorn 2.1.4 + capstone 5.0.7). Memory liên quan: [[store-cipher-is-standard-aes]], [[msp-device-secret-extracted]], [[slot16-native-unicorn-emulates]].

---

## 8. B1 THỰC THI (2026-09-02) — VM emulate ĐÚNG, crypt = static XOR-stream, còn thiếu ĐÚNG key

Dùng `_msp_emu3.py` (init_array 147/147) — VM thunk `0x1119c8` emulate SẠCH. Deliverable mới: `_msp_crypt_emu.py` (class `Crypt`: keymat/sha1name/crypt_keystream/decrypt).

**Giải mã VM (đọc sai struct trước đó = "rác"):** kết quả trả về struct **custom `{u32 cap@0, u32 len@4, ptr data@8}`** (KHÔNG phải libc++):
- `0x10b010(keyname, mode)` = **MD5(keyname)** — mode chẵn=raw16, lẻ=hex32. Khớp `hashlib.md5` chính xác.
- `0x10b13c(keyname, mode)` = **SHA1(keyname)** = filename (chẵn=raw20, lẻ=hex40).
- **read-trace 0x10b010: đọc CHỈ heap(input)+stack+tls+IMG-file. 0 .bss, 0 page tạo bởi on_unmapped ⇒ keymat STATIC-PURE.**

**crypt `0x10bbd0` — ABI + bản chất (verified):**
- ABI (empirical, 4 hoán vị): `0x10bbd0(x0=input MSString, x1=key MSString, x8=out sret MSString)`. Chỉ x0=input xử lý đủ (8873 steps, out=272B=len input).
- **crypt(X) = X XOR keystream(key)**: `crypt(ct)^ct == crypt(zeros)` ⇒ XOR-stream thuần, length-preserving, keystream độc lập nội dung input (không IV từ input).
- **read-trace crypt: đọc CHỈ IMG-file(static)+inputs, 0 .bss/device** ⇒ crypt primitive STATIC (khi đã có key).

**BỨC TƯỜNG CÒN LẠI = ĐÚNG KEY (chưa vượt):**
- keystream đúng (dưới S2: file=crypt(zlib), no len-prefix) phải cho `ks[0:2]=f9b2` (=ct[0:2]^`78 01`). Không ứng viên nào đạt.
- Đã thử **~120 key** qua crypt thật (oracle decompress): MD5/SHA1(keyname) raw+hex, filename, logical forms, const c1167e, **device-secret values (dyn_seed/rtk2_ms/kiid/device_id + hash)**, transform tĩnh của MD5 (đảo/XOR/nối/double-hash). **0 khớp.**
- ⇒ key thật ≠ hash đơn của keyname, ≠ device-secret trực tiếp. Nó do **getter `0x1182d0` dựng** (transform keymat MD5 qua `0x14fe34`/`0x14fa94` trước crypt). Bắt key = emulate getter tới call-site `0x1184a4`.
- **Getter emulation BỊ CHẶN:** getter (và worker `0x12f290`) đều spin ở **logger singleton lazy `[.bss 0x1fbaf8]`** (getter dùng `pthread_getspecific`/TLS → stub trả 0 → đọc global null → vòng `while(!get_logger())`). Pre-seed global + dummy logger object → CPU exception (logger dùng vtable/field cụ thể). Cần emulate C++ logger faithful.

**PHÂN ĐỊNH static-vs-device-gated (chưa dứt điểm, NGHIÊNG static):** keymat MD5 static-pure ✓; crypt primitive static ✓; KHÔNG device-secret value nào decrypt (nếu device-gated, kỳ vọng 1 giá trị device khớp). ⇒ key nhiều khả năng là **transform TĨNH của MD5(keyname)** do getter dựng mà chưa đoán trúng. Xác nhận = capture key qua getter (vượt logger) HOẶC reverse `0x14fe34`+`0x14fa94`.

**Next (thu hẹp):** (1) vượt logger: emulate faithful (getspecific→object hợp lệ + vtable no-op đúng field), HOẶC hook thẳng vòng caller của `0x13af68` để trả sentinel non-null; (2) tới `0x1184a4` đọc x1(key struct)+x0(input) → keystream → verify decrypt; (3) nếu key = f(MD5(keyname)) tĩnh ⇒ FULLY-STATIC decrypt .msp (đóng task). Deliverable sẵn: `_msp_crypt_emu.py`.

**Logger-bypass đã THỬ & THẤT BẠI (2026-09-02, để phiên sau khỏi lặp):**
- (i) hook 0x13af68 trả dummy-object (vtable→ret gadget) → CPU exception (object dùng field/return cụ thể).
- (ii) pre-seed global [0x1fbaf8]=dummy + pthread_getspecific→dummy (fast-path) → CPU exception.
- (iii) crash-proof: map [0,0x200000) toàn `ret` (0xd65f03c0) → ret-bytes bị đọc như CON TRỎ → `blr 0xd65f03c0d65f03c0` → exception.
⇒ Cần dựng logger object ĐÚNG cấu trúc (vtable slot 0x30 = method(this, sp, 0x10006) ghi kết quả vào [sp]; caller đọc [sp]→store [obj+0x10]). Hoặc reverse `0x14fe34`/`0x14fa94` để suy key tĩnh trực tiếp (tránh getter). File thử: scratchpad/getter_cap{,2,3}.py.

---

## 9. ✅ CRACKED (2026-09-02) — .msp FULLY-STATIC decrypt = RC4( MD5(SHA1(keyname)) )

**Disasm trọn setup 0x118400–0x1184a4 lộ key-derivation LỒNG NHAU:**
- `0x118438`: `0x10b13c(x0=descriptor, mode0)` = **SHA1(keyname)** raw 20B → [fp-0x48]
- `0x118448`: `0x10b010(x0=fp-0x48, mode1)` = **MD5( SHA1(keyname)_raw )** hex 32B → [sp+0x40] = **KEY**
- `0x1184a4`: `0x10bbd0(x0=sp+0x50=ciphertext, x1=sp+0x40=KEY, x8=out)`

⇒ **KEY = MD5(SHA1(keyname)).hexdigest()** (32 ASCII). Đó là lý do ~120 ứng viên MD5(name)/SHA1(name) ĐƠN trượt — key là hash LỒNG.
**Cipher 0x10bbd0 = RC4** (emulated keystream == `rc4(key)` byte-exact cho cả .msp_092 & .mss). ⇒ **PURE-PYTHON, không cần emulator.**

**Thuật toán (verified vs cap.noindex/gt_live):**
```
filename  = SHA1(keyname).hex()                 # SHA1("sdi_v2")=092fde7a...
key       = MD5( SHA1(keyname) ).hex()          # = MD5(bytes.fromhex(filename)).hex()  ⇒ chỉ cần FILENAME
keystream = RC4(key)
inter     = ciphertext XOR keystream = [4B LE decompressed-len][zlib]
json      = zlib.decompress(inter[4:])
```

**VERIFY (byte-level + semantic):**
- `.msp_092` (sdi_v2): [4B len]=468 == decompressed 468 ✓; JSON settings hợp lệ; MD5(SHA1("sdi_v2"))=`69c65eb5…`= tên file plaintext capture.
- `.msp_589` (device-secret): [4B len]=494 == 494 ✓; giải ra `kiid=ef86fe33-0264-4b06-ba72-813be3d22158`, `fltk=1787822601249`, `dyn_deviceid=7678616678053643790` — **KHỚP giá trị đã biết** (README bundle + device_id). dyn_version=6 (đã rotate từ 2, tự nhiên).

**Deliverable:** `huongB_devirt19/_msp_decrypt_static.py` (PURE-PYTHON stdlib, no deps): `store_key(keyname)`, `store_key_from_filename(path)`, `decrypt(ct,key)`, `decrypt_file(path)`. Chạy: `python3 _msp_decrypt_static.py <.msp file>`.

**Còn lại (follow-on nhỏ, KHÔNG phải device-secret):** `.mss` (mssdk_setting, 630B) dùng kind KHÁC (không RC4+zlib với key này; kind1 0x10c158/format riêng). Device-secret + settings `.msp` = XONG.

**Kết luận nhánh:** `.msp/.mss fully-static decryptor` — **device-secret + settings CRACKED 100% offline pure-python, verified**. `.msf3`=XXTEA (xong trước). Cả store family giờ giải tĩnh được (trừ .mss mssdk_setting = follow-on).

---

## 10. .mss (mssdk_setting) — characterized, KHÔNG cùng scheme .msp (follow-on riêng)

kind DISPATCH ([x20+4] mod-3): kind0→`0x10bbd0`=RC4(.msp ✓), kind1→`0x10c158`, kind2→`0x10dce0`=XXTEA(.msf3). (Giả thuyết `len%3` BÁC BỎ: .msf3 key len15%3=0 nhưng =XXTEA.)

`.mss` = **kind1 `0x10c158`** (disasm nhánh 0x1184d0: 6 args `0x10c158(x0=in, x1=key, x2=IV-từ-rodata@0x19bb7e via 0x14fc68, x3=&outlen, w4=0, x8=out)`):
- **AES-256** (read-trace: 9227 reads bảng AES 0x196-0x19a) + **STATIC** (0 device .bss).
- **Key = MD5(SHA1("mssdk_setting")).hex** = `5961b61695843f57d754a4220a4161ec` (bắt tại keysched 0x1591bc, keyBYTES=32) — **CÙNG công thức key universal với .msp**.
- NHƯNG: RC4 mọi key-formula & AES-256 CTR/OFB(IV zero/key) đều KHÔNG ra zlib. Block-trace: 80 block-op, block đầu input KHÔNG phải ct (là hex-string `1695616b485975f3…`=nonce/key-material), out 640B(≠plaintext) → sau AES còn `0x15009c` parse. ⇒ `.mss` = **KV-CONTAINER nhiều lớp** (AES-256 + framing per-entry), KHÔNG phải single-blob như .msp.
- ⇒ Follow-on: reverse container format của `0x10c158`+`0x15009c` (multi-pass AES + per-entry parse). Effort riêng; mssdk_setting = settings phụ, KHÔNG phải device-secret.

**Tổng store family:** `.msf3`=XXTEA+MD5(keyname) ✓ · `.msp`(device-secret+settings)=RC4+MD5(SHA1(keyname)) ✓ (crown jewel) · `.mss`(mssdk_setting)=AES-256-container, characterized, chưa parse xong. Key-derivation universal: **MD5(SHA1(keyname))** cho kind0/kind1.

**§10 update — .mss emulation resists quick approaches (2026-09-02):**
- rodata `0x19bb7e` = error-string/mode-flags table (KHÔNG phải IV); `0x14fc68` của nó → chuỗi RỖNG.
- Direct-call `0x10c158(x0=ct, x1=key, x2=IV, x3=&outlen, w4=0 và 1, x8=out)`: cả 2 hướng ra CÙNG 640B rác (630 pad→640) — không zlib.
- Block-trace: 80× `0x159618` với x0 = **CÙNG** `1695616b485975f3…` (diff=0) ⇒ nhiều khả năng x0 = **AES key-context** (cố định), data-block ở reg khác ⇒ ABI block giả định SAI ⇒ phân tích .mss chưa đáng tin.
⇒ `.mss` cần RE CHUYÊN SÂU riêng cho `0x10c158` (xác định đúng ABI AES block + pattern 80-block/KDF + container `0x15009c`), HOẶC full-getter emulation (vượt logger). Giá trị thấp hơn device-secret. **Đóng nhánh `.msp/.mss` ở đây với device-secret CRACKED + .mss characterized.**

---

## 11. RE SÂU 0x10c158 (.mss) — AES-256 standard confirmed; .mss = KV-CONTAINER (2026-09-02)

**Block cipher xác định CHÍNH XÁC:**
- `0x159618` ABI = `aes_block(x0=AES_KEY schedule, x1=input16, x2=out16)`. (Trước nhầm x0=input ⇒ 80 "input" giống nhau vì x0=key-ctx cố định.)
- `0x159618` = **AES-256 ENCRYPT chuẩn**: `_aes_pure.encrypt_block(key, mss[:16])` == emulated block-out `4fd6b1f34d908955…` **byte-exact**.
- Key (bắt tại keysched `0x1591bc`, keyBYTES=32) = `MD5(SHA1("mssdk_setting")).hex` = `5961b616…` — **universal key derivation** (giống .msp).
- EVP dispatcher `0x10d124`: mode-byte từ ctx → jump-table `0x18fa28` → mode0=ECB-loop(0x159618/block), mode khác=0x159de4/0x15a2b8/0x15a628.

**.mss = KV-CONTAINER (không phải single-blob):** faithful slice từ `0x118400` (stub 0x175e5c→file, x20=keyname "mssdk_setting" len13→kind1, để lib preprocess): AES-input (sp+0x50 sau `0x10e7f0`) = **17B `[len=2][78 01 zlib]`** = MỘT entry dạng `[4B len][zlib]` (cùng inner-format .msp). ⇒ `0x14fc68`+`0x10e7f0` **parse container 630B → entries**; `0x10c158`(AES-256) bọc framing. Khớp STATUS cũ "msp/mss = KV-database container".

**Trần thật:** black-box (RC4/AES stream mọi IV) + slice-emulation đều KHÔNG faithful (thiếu chuỗi parse container + đúng ctx/mode/direction). Giải `.mss` cần **faithful FULL-getter emulation** (container-parser 0x10e7f0/0x14fc68 + crypt 0x10c158 + qua logger singleton [0x1fbaf8]) HOẶC reverse tường minh format container (framing per-entry + layout 630B). = sub-project multi-component riêng.

**Đã xác định (đủ để tiếp sau):** cipher=AES-256 standard, key=MD5(SHA1(keyname)) universal, inner-entry=`[4Blen][zlib]`, container-parser=0x10e7f0/0x14fc68, crypt=0x10c158 mode-dispatch 0x10d124. Chưa: layout framing 630B + đúng read-direction. **Device-secret .msp = XONG; .mss = characterized sâu, chờ faithful full-getter.**

**§11 update — .mss pipeline không cắt-lát faithful được (2026-09-02):**
- Full getter 0x1182d0 (không stub 0x175e5c) → CPU exception; 0x175e5c KHÔNG dùng fopen (không phải file-I/O trực tiếp — trả cached/computed value).
- Slice 0x118400 + stub 0x175e5c→mss(630B): `0x10e7f0` output = 17B `[len=2][zlib]` → decompress = `b'v\x02'` (2B). 630B→2B vô lý ⇒ setup slice SAI (object/descriptor/container-parse đan xen, manual setup không tái hiện đúng).
- Đã thử TRỌN: black-box RC4/AES mọi mode+IV; direct-call 0x10c158 (w4=0/1); slice 0x1184d0; slice 0x118400; full getter 0x1182d0; block-trace (AES-256 std confirmed); keysched capture (key=MD5(SHA1(keyname))). Consistent blocker = **faithful full-pipeline emulation**.
⇒ `.mss` cần: (A) faithful full-getter (object 0x1182d0 + logger bypass đúng-cấu-trúc + container-parse chạy tự nhiên), HOẶC (B) static devirt CFF của `0x10e7f0`+`0x10c158`+framing (multi-day). = **dedicated sub-project**, KHÔNG phải quick continuation. Mọi THÀNH PHẦN đã map (AES-256 std, key universal MD5(SHA1(keyname)), inner `[4Blen][zlib]`, funcs 0x175e5c/0x14fc68/0x10e7f0/0x10c158/0x15009c). Device-secret `.msp` = XONG.

---

## 12. .mss RE ADVANCE (2026-09-02, claude solo) — 0x10c158 = std AES-256-ECB ENCRYPT (write-primitive); all standard modes ruled out cleanly

**Mục tiêu:** tiếp follow-on `.mss` (mssdk_setting 630B) — hướng MỚI: mổ byte-layout + disasm setup (con đường đã crack `.msp`), KHÔNG lặp lại black-box/emulation cũ.

**Đọc disasm getter/setter 0x1182d0 (nhánh kind1 tại 0x1184d0) — LEGIBLE, chốt ABI thật:**
- `0x1184e0 0x14fc68(x1=rodata 0x19bb7e)` → **rodata@0x19bb7e = `\x00\x02\x03...` (byte đầu = NUL)** ⇒ std::string **RỖNG**. Vậy param x2 của 0x10c158 = `""` (SỬA red-herring "IV từ rodata" §10).
- Call: `0x10c158(x0=input sp+0x50, x1=key sp+0x40=MD5(SHA1(keyname))=5961b616…, x2="" , x3=&outlen, w4=0, x8=out)` → `0x15009c(dst, out)`.
- `0x15009c` = std::string **move/append helper** (legible, KHÔNG decompress). Toàn bộ crypto ở trong 0x10c158.
- Input crypt = sp+0x50 = `0x10e7f0(string(0x175e5c()))` — CÙNG loader với kind0 (.msp). Vì .msp = RC4(key, RAW-FILE) verified ⇒ loader ≈ passthrough file bytes.

**FAITHFUL EMULATION 0x10c158 (deliverable `_mss_emu.py`, dùng harness `_msp_emu3.py` init_array 147/147):**
- Reached RET SẠCH. **Mode-probe (encrypt 3 khối giống nhau) ⇒ out 3 khối GIỐNG NHAU + khớp byte-exact `_aes_pure.encrypt_block`** ⇒ **0x10c158 = AES-256-ECB ENCRYPT chuẩn** (không CBC: cbc-iv0 predict b1 ≠). w4∈{0,1,2} KHÔNG đổi output ⇒ w4 KHÔNG phải direction.
- out[0:16] = AES_enc(key, mss[:16]) = `4fd6b1f3…` (khớp block-trace §11 — đó là ENCRYPT khối data, không phải IV).

**0x118400 = WRITE path** (tail: `ldr w8,[sp,#0x34]; cmp #1; …; bl 0x12e79c`=fopen/fwrite). ⇒ on-disk = ENCRYPT(plaintext). `.msp` decrypt được vì RC4 đối xứng (enc==dec); `.mss` = AES ⇒ cần INVERSE (decrypt), nằm ở read-branch trong graph CFF.

**LOẠI TRỪ SẠCH (pure-python, không black-box mơ hồ) — key=5961b616… (ascii32 AES-256) & raw16 (AES-128):**
- ECB-decrypt file mọi alignment {0,2,4,6,8,10,14} → rác (37-40% ascii, 0 zlib, 0 PKCS7 tail).
- CBC-decrypt (IV∈{0,key16,raw16,md5kn,prev-block}) → rác.
- CTR/OFB/CFB toàn-file + IV=file[:16] (embedded) → rác. **CFB đặc biệt: pt[16:] IV-ĐỘC-LẬP vẫn 37% ascii** ⇒ KHÔNG phải CFB.
- Outer RC4(key) rồi soi → rác. ⇒ on-disk ≠ AES(key, plaintext) ở BẤT KỲ mode chuẩn nào.

**TRẦN THẬT (xác nhận độc lập, khớp §10/§11):** getter 0x1182d0 + crypt 0x10c158 đều **CFF-flattened + VM-dispatch** (`blr 0x11877c`/`0x1119c8`, opaque madd/umull, ret-trampoline). Read/decrypt-branch KHÔNG phải sibling legible — nằm trong graph phẳng. Write dùng ECB-encrypt (island legible) nhưng ECB-decrypt KHÔNG đảo được file ⇒ giữa ECB-block và file còn **container-framing/EVP mode-wrap** (jumptable 0x18fa28: mode0=ECB, mode khác 0x159de4/0x15a2b8/0x15a628) mà direct-call bỏ qua.

**KẾT LUẬN NHÁNH:** `.mss` cần 1 trong: (A) faithful FULL read-getter emulation (vượt logger singleton [.bss 0x1fbaf8] — prior thử 3 cách FAIL); (B) devirt CFF read-branch + mode-dispatch (multi-day); (C) capture-once live (cần phone; giá trị phụ). **Device-secret `.msp` = XONG (crown jewel). `.mss` = characterized ĐẦY ĐỦ tới primitive+key+write-direction; chỉ thiếu inverse-pipeline.** Deliverable mới: `_mss_emu.py` (faithful AES-256-ECB oracle + 6-arg 0x10c158 harness — tái dùng cho pipeline-emulation sau).

---

## 13. .mss HEAVY EMULATION (2026-09-02, claude solo, user chose option 2) — LOGGER SINGLETON WALL BROKEN

**User chọn "emulate full-getter nặng". Kết quả: vượt logger singleton (chỗ prior FAIL 3 lần) + emulation chạy tới clean-return.** Deliverables: `_mss_getter.py` (stateful pthread TLS), `_mss_getter2.py` (full: TLS + logger-bypass + syscall VFS).

**Các tường đã vượt (theo thứ tự, mỗi cái là 1 blocker riêng):**
1. **pthread TLS stateful** — emulator cũ `pthread_getspecific`→0 luôn, `setspecific`→no-op ⇒ singleton lazy-init KHÔNG BAO GIỜ cache ⇒ caller spin `while(!get_logger())`. Fix: `tls={}`, `key_create`→id mới, `setspecific(k,v)`→tls[k]=v, `getspecific(k)`→tls[k], `once`/`__call_once`→chạy init ĐÚNG 1 lần.
2. **Logger singleton `0x13af68`** (chỗ prior FAIL): getter đọc global sink `*(0x1efbd8)`; nếu null → `ret null` (KHÔNG cache) → spin. Fix: **pre-seed `*(0x1efbd8)`=self-ref safe obj** + **bypass 2 vtable-call** của sink (`0x13b010` slot+0x30 ghi result ptr vào [sp]; `0x13b034` slot+0x20 void). Sau đó construct hoàn tất → `pthread_setspecific` cache → spin dừng.
3. **Inlined `svc #0` syscalls** (anti-tamper inlined-svc, khớp memory): emulator không handle → CPU exception. Fix: `UC_HOOK_INTR` VFS — openat/read/lseek/fstat(st_size@0x30)/close/mmap phục vụ nội dung file + getrandom/clock/futex benign.
4. **Vtable cascade nông** (chỉ 3 null-blr: 0x13b010/0x13db50/0x13b364) — KHÔNG phải object-graph vô tận như lo ngại.

**PHÁT HIỆN QUAN TRỌNG — `WORKER=0x12f290` là HÀM GHI (writer), KHÔNG phải reader:** disasm prologue lộ: build path (`0x1509c0` %s/%s%s, dir@0x1909a0 + suffix csel theo kind), **fopen `0x16facc`**, **3× fwrite `0x171c58`**: `fwrite(&len,8,1)`+`fwrite(&field,8,1)`+`fwrite(data,1,len)`, fclose `0x16fe34`. ⇒ `_msp_emu3.py` cũ trỏ SAI hàm (đó là lý do worker ra 0B cho CẢ .msp). I/O primitive `0x12e79c` = READ (fopen+fread `0x171d70`), unified read/write theo mode-arg w3=[x19+0x48]?2:0.

**CÒN LẠI (well-defined, infra đã sẵn):** tìm + drive đúng READ+DECRYPT entry (không phải 0x12f290 writer). Store là unified get/set CFF (0x1182d0) dùng crypt mod-3 (kind0=0x10bbd0 RC4, kind1=0x10c158 AES-ECB-ENCRYPT, kind2=0x10dce0 XXTEA) + I/O 0x12e79c. Reader cho kind1 phải dùng AES-DECRYPT (sibling của 0x10c158, chưa định vị) HOẶC 0x1182d0 với ctx read-mode. Infra `_mss_getter2.py` (TLS+logger+VFS) giờ chạy store-fn tới clean-return ⇒ chỉ cần đúng entry+context. Đây là bước tiến LỚN qua wall note 56 §12 (prior "logger FAIL 3 cách" → nay SOLVED).

**Store ARCHITECTURE mapped (Ghidra decompile, 2026-09-02):**
- Reader item pattern `FUN_0023ab30` (MSSPItem_v2): DB-read(container,itemkey via `0x11a64c` op 0x1000022) → ct → **unhex `0x1891f4`** → **decrypt `0x10e224`(out, unhexed_ct, key=MD5(itemkey) via `0x10b010`)** → value. ⇒ item-layer decrypt = **0x10e224** (KHÁC 0x10c158 writer!), key=MD5(itemkey), ct hex-encoded.
- Device-secret loader `FUN_002349ac`: đọc store handle `FUN_002185d0()` rồi query keys "rdk2_ms/rtk2_ms/rsk2_ms" qua **`FUN_00217e94(store, keyname)`** (=value-get) → unhex rtk2_ms. ⇒ loader thao tác trên store ĐÃ giải mã.
- ⇒ File→plaintext decrypt nằm ở **store-LOADER** (đọc .mss → giải mã → in-memory map), tách khỏi item-access. Next: định vị mssdk_setting store-loader, emulate `FUN_002185d0`+VFS(.mss) → DUMP decrypted store memory = plaintext. Infra `_mss_getter2.py` sẵn sàng drive.

**mssdk_setting accessor localized (0x6bbc0, 2026-09-02):** string "mssdk_setting"@rodata 0x17c66c, ref DUY NHẤT tại code 0x6bbd4. Accessor: `x20=*(0x1f41d0)`(store-manager global) → filename=SHA1("mssdk_setting") (0x10b13c) → concat 0x151ec0 (string helper, KHÔNG phải loader) → DB ops `0x12ee10`(0xe1070)/`0x65a7c`/`0x118ba4`/`0x118e54`. ⇒ **`.mss` = serialized KV-DATABASE container** đọc qua store-manager `*(0x1f41d0)` + DB engine (0x11a64c op-codes), KHÔNG phải single-cipher blob như .msp(RC4)/.msf3(XXTEA). Đó là lý do MỌI whole-file AES mode fail: file = DB framing + per-item ECB, không phải 1 khối.

**TRẦN CUỐI (honest):** giải .mss = emulate/reverse DB engine (store-manager init + container parse + per-item unhex+decrypt 0x10e224 với MD5(itemkey)). Infra `_mss_getter2.py` (logger wall BROKEN) chạy được store-fn tới clean-return, nhưng drive DB-engine end-to-end cần khởi tạo store-manager subsystem (*(0x1f41d0) + DB structs) = effort lớn. Wall chính (logger) đã phá; phần còn lại là subsystem C++ nhiều tầng. Device-secret .msp = XONG (crown jewel). .mss = auxiliary settings, characterized TRỌN + wall phá, chờ quyết định có drive DB-engine tiếp không.

---

## 14. .mss DB-engine drive (2026-09-02, opt2 continued) — accessor localized, DB-engine needs object-graph reconstruction

**mssdk_setting accessor = `0x6bb84`** (string ref DUY NHẤT 0x6bbd4). Emulate end-to-end (VFS+logger-bypass): **reached clean-return `pc=0x800` NHƯNG opens=[] (KHÔNG đọc file)** — store load KHÔNG xảy ra lúc access. Lazy-init 0x6bf34 chỉ dựng 6-byte keyed obj `8b7ff2a43f10`@*(0x1f41d0), không phải store-manager. Mem-scan sau access: chỉ static strings (integrity_response/mssdk_setting/URL-template/filename `.mss_9b8ed99…`), KHÔNG có plaintext.

**Vì sao không load:** null-blr autoskip=6 gồm các **vtable-call của store-manager/DB object** (null vì object CHƯA construct). Store-manager (*(0x1f41d0) region), DB engine (0x11a64c), container ops (0x12ee10/0x118ba4/0x118e54) đều là runtime C++ objects dựng lúc SDK init (không phải init_array 147 ctor). Callers: read-io 0x12e79c ← {0xb13ac, 0x118560}; AES-decrypt 0x10e224 ← {0x11917c, 0x12fce0, 0x13ac3c=item-reader}. Store name siblings @rodata: st1/st2/st3/mssdk_setting/bootso.

**KẾT LUẬN opt2 (honest):** để ra plaintext `.mss` cần **dựng store-manager + DB object-graph** (constructors + vtables của store-manager/DB/container) rồi drive load(read .mss qua VFS)+parse+decrypt-per-item — hoặc reverse tường minh format DB serialization. = **multi-session sub-project**. TƯỜNG CHÍNH (logger singleton) ĐÃ PHÁ (infra `_mss_getter2.py` reusable). Roadmap còn lại well-defined nhưng lớn. `.mss` = auxiliary settings, giá trị thấp vs device-secret `.msp` (XONG). Deliverables session: `_mss_emu.py`(ECB oracle), `_mss_getter.py`(TLS), `_mss_getter2.py`(logger-bypass+VFS), `_mss_load.py`(accessor drive+mem-scan).

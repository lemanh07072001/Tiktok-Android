# 51 — CRYPTO ĐÃ ĐỊNH DANH: slot16 = hash native (SHA-1/SM3), VM 0x52924 = marshaller

> Nối tiếp note 50. Phiên 2026-08-27, nhánh A (grind static offline). Zero môi trường — chỉ `objdump` trên `bin/libmetasec_ov.so`.

## 0. TL;DR (đảo chiều chiến lược)
- Kế hoạch cũ ("enumerate context x30 khác để tìm VM-ARX slot16") **SAI PREMISE**. Không có VM-ARX.
- **VM context 0x52924 = marshaller/serializer** (đã xác nhận: 47 handler, `eor=0 ror=0` toàn bộ — không handler nào chứa XOR/rotate ⇒ không thể là ARX).
- **Crypto slot16 = code NATIVE, không phải opcode VM.** Định danh chắc chắn bằng round-constant:
  - **SHA-1** @ `0x15bb00` (compression, unrolled 80 vòng) — K0..K3 + IV đủ.
  - **SM3** @ vùng `0xa07c8` (Tj `0x79cc4519`) — đã dùng cho #19 (SM3(query‖slot16‖'0'), 11/11 bit-exact, note "done" cũ).
- **slot16 (16B) = truncate-16B của hash trên MESSAGE ĐÃ MARSHAL** — KHÔNG phải hash concat field đơn giản (brute 3 tuple × mọi layout/HMAC = trượt sạch).

## 1. Bằng chứng phân loại 47 handler (context 0x52924)
Script: sửa parse mnemonic (objdump: mnemonic ở `split('\t')[1]`, không phải `[2]`), disasm 0x80B/handler, đếm category.
- Toàn bộ 47 handler: **eor=0, ror/extr=0**. Đa số `add/sub/and/orr` (marshal/gather protobuf).
- ⇒ khớp kết luận note 50 §7: op40=0xf6b58 = MARSHAL. Cả bảng là VM serialize, crypto ở tầng khác.

## 2. Quét ARX toàn `.text` → định vị crypto native
Cửa sổ trượt 48 lệnh, đếm `eor/ror/extr/rev/rbit`. Vùng đậm đặc nhất:
```
arx=45  0x15c000..0x15c0bc   <- gần thuần rol1+eor (message schedule / diffusion)
arx=28  0x15cac0 / 0x15be00 ; 24 @0x15c8c0 ; 22 @0x15c400 & 0x0a0d34 ...
```
Cụm `0x15b000..0x15c400` = **một hàm** (prologue @`0x15bb00` `sub sp,#0x120`), gọi 2× → hàm hash lớn.

## 3. Định danh = SHA-1 (round-constant là vân tay mạnh nhất)
Histogram hàm 0x15bb00: `eor187 add114 ror113 bic20 and20 orr20 rev16 movk4`.
movz/movk immediates dựng lại 32-bit:
```
0x5a827999  (mov w30,#0x7999; movk #0x5a82,lsl16)  = SHA1 K0
0x6ed9eba1                                          = SHA1 K1
0x8f1bbcdc                                          = SHA1 K2
0xca62c1d6                                          = SHA1 K3
0xc3d2e1f0                                          = SHA1 IV h4
```
- `rev`×16 = byte-swap big-endian nạp W[0..15]. `ror #0x1f`=rol1 (W schedule), `ror #0x1b`=rol5, `ror #2`=rol30.
- `bic/and/orr` = hàm Ch (vòng 0-19) / Maj (40-59). ⇒ **0x15bb00 = SHA-1 compression**, wrapper @`0x15ba28` (init IV + finalize, gọi compression 2×).
- "Custom ARX ror/eor/add" mà note 39/42 mô tả cho slot16 **thực chất là SHA-1**, không phải primitive tự chế.

Kiểm kê constant toàn `.text` (chỉ 2 thuật toán lộ diện):
```
SHA1  K0..K3 + h4   @0x15bXXX..0x15c9XX
SM3   Tj 0x79cc4519 @0xa07c8
```

## 4. Control-flow bị tính-toán-hoá (obfuscation) — trace tĩnh call-graph BỊ CHẶN
- SHA-1 compression 0x15bb00: chỉ 2 bl-caller (0x15ba90, 0x15bab4 — cùng wrapper 0x15ba28).
- Wrapper 0x15ba28: **0 bl-caller trực tiếp + 0 con trỏ 64-bit trong file** ⇒ tới qua **con trỏ tính-toán runtime** (giống dispatch VM `table_ptr + f(x30)`). Không lần ngược caller bằng `bl` tĩnh được.
- SM3 0xa07c8: 0 bl-caller trực tiếp ⇒ tới qua **con trỏ hàm trong descriptor-table của marshal-VM** (0x1dd000/0x1de/0x1df).

## 5. slot16 KHÔNG phải hash-concat đơn giản (đã loại trừ)
Ground-truth `_clean_tuples.json`: 3 tuple cùng keva/device, khác `_rticket/ts`:
```
rt=1787492671771 ts=1787492671 slot16=dbc927b5d95a976dd536fd319a609e77
rt=1787492672070 ts=1787492672 slot16=528c1749aaaa6bb985cf445ee1a1ad3f
rt=1787492716235 ts=1787492716 slot16=0368525bbc8948577a33284cac9c660d
psk_material_32B=c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163
keva.ecneuq=94199bca6d60ed2e  keva.semithc=06c89feae2d013cceab9ad17  device_id=7666223875861513749
```
Brute (yêu cầu khớp CẢ 3 tuple): sha1/md5/sm3/sha256 × {plain,HMAC(psk)} × offset{0,4} × mọi layout
`A + enc(rt) [+ B + enc(ts)]` với A,B ∈ {'',psk,psk halves,keva,did} × enc ∈ {ascii,LE/BE 8/4B} = **0 hit**.
Quét mọi hex-blob trong file capture, `hash(blob)[:16]` vs slot16 = **0 hit** (captures không chứa buffer tiền-hash).
⇒ Input hash = **message marshal thật** (cấu trúc protobuf), phải tái tạo mới hash được.

## 6. Nút thắt chính xác + hướng đi
**Để sinh slot16 offline cần đúng bytes đưa vào hash.** Bytes đó = output marshal-VM (0x52924). Không có capture (env chết) + không có cặp (input→slot16) sẵn.

Hai sub-route để lấy input marshal:
- **(A) Trích SCHEMA từ descriptor-table** 0x1dd000/0x1de/0x1df (mỗi entry ~ {field_tag, wire_type, offset, handler_ptr}). Marshal-VM là **serializer protobuf generic driven-by-descriptor** ⇒ KHÔNG cần lift 47 opcode; chỉ cần schema + giá trị field → re-serialize bằng protobufjs → hash. Tractable hơn nhiều.
- **(B) Capture 1 lần** buffer tiền-hash (env chết → cần human khôi phục emulator/frida).

**Câu hỏi mở quyết định khả thi (chưa giải):** slot16 có **deterministic** theo (PSK, _rticket, ts) không, hay có **nonce ẩn per-run**?
- Note cũ (40-44): A/B run cùng query **DIVERGE** ⇒ có nonce per-run; nhưng cũng ghi "**server chấp nhận CẢ 2 divergent ⇒ không exact-match**" (register). Nếu đúng cho path này → chỉ cần **mint slot16 hợp-lệ**, không cần khớp chính xác server-expected.
- 3 clean tuple là **cặp đã match từ capture** ⇒ nếu có nonce ẩn thì không tái tạo được value CỤ THỂ này offline; nếu deterministic thì tái tạo được khi có construction + PSK.

## 7. Tool/tái lập
- `_vm_static_decode.py <so> <x30>` — decode bảng dispatch (note 50).
- Classifier 47-handler + ARX-scan + constant-scan: inline script (phiên này), tái chạy bằng objdump.
- Verify SHA-1 ID: `objdump -d --start-address=0x15bb00 --stop-address=0x15c400 bin/libmetasec_ov.so | grep -E 'movk|#0x(7999|eba1|bcdc|c1d6)'`.

## 8. REFRAME quan trọng (dữ liệu ground-truth device 7666) — slot16 KHÔNG phải hash(query)
Có 11 cặp `(query, slot16)` trong `ground-truth/hash19_nonzero_tuples.json` (device AVD 7678, psk KHÔNG rõ) — test `slot16 = H(query)[off:16]` unkeyed (sm3/sha1/sha256/md5, mọi offset/window) = **0 hit** ⇒ slot16 KHÔNG phải hash trần của query. (Xác nhận SM3 tôi bit-exact: `sm3(query‖slot16‖'0')==digest_std`.)

**Dữ liệu device 7666 (đủ input + target, dùng để verify offline):**
- psk 32B = `c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163` (đã xác nhận khớp offline-unidbg).
- keva stable: ecneuq(8B)=`94199bca6d60ed2e`, semithc(12B)=`06c89feae2d013cceab9ad17`, wayval=`d8b4d76cf5fabed1a711b5de`/`08a39e6765657586`, count-keys.
- **target slot16_PSK_state = `0368525bbc8948577a33284cac9c660d`** (`_matched_tuple.json`).
- seed 4B ví dụ (`_live_session`): `1a62b24e`, `b6a0012b` (per-request, KHÔNG paired với slot16).

**slot16 = giá trị DEVICE-STABLE từ pool, KHÔNG phải hàm thuần _rticket:**
`0368525b…` xuất hiện với 2 `_rticket` KHÁC nhau (matched_tuple rt=1787491636229 vs clean tuple2 rt=1787492716235). key_facts (`_matched_tuple`): "cross-session STABLE, deterministic, computed runtime từ stable inputs, KHÔNG lưu raw; **≠ mọi hash/HMAC/XOR đơn giản** của (psk,ecneuq,semithc,wayval) → **deeper AES derivation**".

**Loại trừ (phiên này, brute pure-python):** slot16_state ≠ AES-ECB/CBC-MAC(psk|psk-halves, mọi block ghép từ stable fields) enc/dec; ≠ SHA1/SM3/SHA256/MD5(field-concat). ⇒ F = KDF native tổ hợp NHIỀU bước.

## 9. Bộ công cụ crypto native đầy đủ (định vị bằng constant/table)
```
AES     T-table Te0 @0x198fe4  (impl table-based; "AES OUTER" là thật)
SHA-1   compress @0x15bb00, update-wrapper @0x15ba28 (streaming chuẩn, KHÔNG nonce)
SHA-256 K-table @0x19b540
SM3     Tj @0xa07c8 (dùng cho #19, 11/11 bit-exact)
```
slot16-producer F = tổ hợp các primitive này (deep KDF trên PSK). **BƯỚC KẾ để lift F tĩnh:** xref data tới Te0 `0x198fe4` (adrp+add 0x198000) → hàm AES-encrypt native → lần caller ra producer PSK-state → deobfuscate computed-flow → lift F → verify vs target `0368525b…` (device 7666, đủ input). Tool: `_aes_pure.py` (AES KAT-verified), `_vm_static_decode.py`, SM3 inline (bit-exact).

## 10. AES-encrypt native ĐÃ ĐỊNH VỊ + tường obfuscation cao đúng 1 nấc trên leaf
Xref Te-table (phiên này): **chỉ 1 vùng** ref đồng thời trang 198/199/19a = hàm AES-encrypt table-based.
- **Entry chính `0x1591bc`** (9 bl-caller), entry phụ `0x159618` (2×, AES-dec/key-sched?). Base hàm `0x1590c0`.
- Cấu trúc round xác nhận bit-đối-bit: `lsr/ubfx` tách 4 byte cột → `and #0x3fc`/`lsl #2` index → `ldr` Te0..Te3 → `eor×3` = T0^T1^T2^T3.
- **4 T-table**: Te0=`0x197fe4`, Te1=`0x1983e4`, Te2=`0x1987e4`, Te3=`0x198be4` (mỗi cái 1KB). (Note §9 ghi `0x198fe4` là bảng thứ-5 = Te round-offset/Td, KHÔNG phải Te0.)
- Các "vùng AES" khác trong xref (page 19b000) THỰC RA trỏ K-table SHA-256 `0x19b540` → đừng nhầm.

**Tường obfuscation (quyết định khả thi nhánh A):**
- Leaf AES-enc `0x1591bc` CÓ 11 bl-caller tĩnh → leo được ĐÚNG 1 nấc.
- Nhưng caller đó — consumer `0x10d068` + mode-wrapper `0x159ffc` — đều **0 bl-caller + 0 con trỏ 64-bit file** ⇒ tới qua con trỏ tính-toán runtime (y như dispatch VM, SHA-1 wrapper 0x15ba28, SM3).
- ⇒ **Kết luận cứng:** computed-flow obfuscation là HỆ THỐNG. Chỉ tầng leaf lộ `bl`; MỌI hàm tổ-hợp trên (kể cả F) vào bằng con trỏ materialize-runtime. **Trace `bl` tĩnh tới F BỊ CHẶN đúng 1 nấc trên leaf.**

**Hệ quả branch A:** lift F thuần-tĩnh = **đánh sập tầng computed-flow** (tái dựng materialize con trỏ cho crypto-wrapper, như đã crack `f(x30)` cho dispatch VM nhưng làm lại + F nhiều bước). Effort nhiều ngày, bất định.

**2 lối còn lại (fork cần human):**
- (A-hard) Defeat computed-flow tĩnh: emulate lớp dispatch/pointer-materialize → biết wrapper nào=F + thứ tự primitive.
- (B) Dynamic capture 1 cặp (input→slot16)/buffer tiền-hash — chặn bởi env chết (cần khôi phục emulator/frida).

**Phân biệt 2 "slot16":** (1) slot16 cho #19 = INPUT sẵn từ ground-truth, #19=SM3(query‖slot16‖'0') ĐÃ bit-exact ⇒ xong khi có slot16. (2) slot16_PSK_state `0368525b…`=F(PSK,keva…) = tường thật còn lại.

## 11. TẦNG COMPOSE F = pointer-table 17 entry @0x1f3688 (defeat obfuscation lối data-driven)
Chọc thủng "computed-pointer wall" bằng lối KHÁC (không trace bl): quét reloc `R_AARCH64_RELATIVE`.
- Chỉ **1 addend** rơi vào vùng crypto: slot `.data` @`0x1f36c0` = `0x10d1ec` (= consumer AES `0x10d068`+0x184).
- Slot đó nằm trong 1 **bảng con-trỏ-hàm 17 entry @`0x1f3688..0x1f3708`** (raw offset module-relative vào .text):
```
[0] 0x14fad8  [1] 0x172d28  [2] 0x151508  [3] 0x1458d4  [4] 0x117580  [5] 0x10baa8
[6] 0x145d5c  [7] 0x10d1ec(AES-consumer)  [8] 0x14fe1c  [9] 0x14fe34  [10] 0x99fac
[11] 0x76670  [12] 0x14fad8  [13] 0x1461a8  [14] 0x76628  [15] 0x14642c  [16] 0x12c268
```
- `0x14fad8` (index 0 & 12) = report-assembly/orchestrator đã biết (BOARD: keva-put/serialize cluster 0x14fxxx).
- Bảng KHÔNG ref bằng `adrp 0x1f3000+#0x688` cố định ⇒ con-trỏ-bảng giữ trong struct/reg, index động runtime — chính là descriptor-driven dispatch (khớp dự đoán §4: SM3 tới qua descriptor-table).

**Ý nghĩa:** đây là **tầng compose F** (pipeline ký) — F không phải 1 hàm liền mà là chuỗi gọi các entry bảng này theo thứ tự do state/opcode quyết định. AES-consumer (index 7) là 1 mắt xích. Để lift F tĩnh: (a) tìm ai nạp con-trỏ-bảng `0x1f3688` + biến index → biết trình tự gọi; (b) lift từng entry (0x14fad8/0x151508/0x1458d4/0x10d068…) = ~10 hàm; (c) ghép chuỗi → F. Vẫn nhiều ngày nhưng **có bản đồ cụ thể** (17 entry đóng khung), không còn "tường mù".

**Bank:** đây là bước tiến thật — chuyển từ "computed-flow tường mù" sang "descriptor-table 17 entry đã đóng khung". Verify: reloc-scan + `.data` dump @0x1f3688 tái lập bằng script phiên này.

## 12. ĐẢO CHIỀU: code ĐỌC ĐƯỢC (không CFF) + AES-subsystem map + brute AES CẠN
**Sửa lỗi lớn:** "tường CFF/computed-flow" trước đây BỊ PHÓNG ĐẠI. Thân hàm là **ARM64 SẠCH, lift được**:
- `0x10d068` = **AES-facade theo mode**: memset outbuf(528B) → đọc tag(0..3) từ struct → `br` jump-table (switch compiler chuẩn, KHÔNG obfuscation) → gọi 1/4 AES: `0x1591bc`(ECB core) / `0x159d60` / `0x15a1dc` / `0x15a598` (mode + key x3).
- `0x10d124` = **AES-facade DECRYPT** (đối xứng, gọi 0x159618/0x159de4/0x15a2b8/0x15a628). = table entry idx7 (0x10d1ec).
- "0 bl/0 ret" ở §11 census = **bug parser của tôi** (`split('\t')[2]`), không phải CFF.
- ⇒ Obfuscation THẬT chỉ gồm: (a) computed-dispatch đỉnh VM (đã giải, note 50), (b) gọi gián tiếp qua bảng reloc `.data`. Thân hàm crypto/serialize đọc thẳng objdump được.

**AES subsystem (đầy đủ):** block-core `0x1591bc` (+entry phụ `0x159618`) ← mode-wrappers `0x159d60/0x15a1dc/0x15a598` ← facade enc `0x10d068` / dec `0x10d124`. T-table Te0..Te3 @0x197fe4/1983e4/1987e4/198be4.

**keva-key strings CÓ trong .rodata:** `semithc`@`0x191e78`, `ecneuq`@`0x191e80`. Consumer cluster `0x12f830..0x12fd48` (6 hàm) đọc keva qua helper `0x14fxxx` (keva get/put) — KHÔNG gọi AES trực tiếp ⇒ KDF sâu hơn (trong bytecode VM).

**TOOLING offline (ràng buộc cứng):** KHÔNG có unicorn/capstone/keystone (import fail cả 3). ⇒ chỉ objdump thuần, **không auto-emulate/deobf** — phải lift bằng đọc disasm tay.

**Brute AES CẠN KIỆT (pure-python _aes_pure, device 7666):** target `0368525b…` ≠ mọi:
ECB/dec/enc2/CMAC/CTR × key{psk32,psk16,psk_hi,psk^halves, sha256/sha1/md5(psk), sha256(psk|wv1), wv1|wv2}
× block/msg{ecneuq,semithc,wayval(d8b4d7…/08a39e…),did, mọi ghép} = **0 hit**. ⇒ F = **tổ hợp NHIỀU bước** (không single-AES), phải lift bytecode.

**BƯỚC KẾ đã khoanh (BOARD cff-deobf card):** slot16 = **VM-program `0x191f40`** (call-site `0x1384e4 bl 0x52924`; x1=inbuf object-graph, x2=tableA `0x1e0530`, x3=tableB `0x1e0560`, x4=outbuf=slot16). Program marshal + gọi native AES/SHA. Lift = decode opcode stream 0x191f40 (dùng handler-table note 50) + map native call-out. Đa phiên nhưng đã có toạ độ + code readable.

## 13. KIẾN TRÚC VM VỠ HOÀN TOÀN — F = interpreter(prog 0x191f40) [MILESTONE]
**F call:** `0x1384e4 bl 0x52924` với x0=prog`0x191f40`, x1=input object-graph(sp+8), x2=tableA`0x1e0530`, x3=tableB`0x1e0560`, x4=outbuf(slot16).

**Interpreter 0x52924 (register-machine, KHÔNG phải marshaller thuần):**
- **Dispatch chính @0x55890:** `PC=[x23]; w=[PC]; op = w & 0x3f` (BYTE THẤP — xác nhận). base=`*(0x1f00e0)+f(x30)`; `handler=[base+op*8] − bias`; `br`. bias=**0x9b374** (`mov w13,#0xb374;movk #0x9,16;stur [x29,-0x58]`). ⇒ handler thật = raw−0x9b374, cụm **0x52b4c..0x5ccfc** (inline trong thân interpreter).
- **47 handler** decode đúng qua `_vm_static_decode.decode_context(0x52924, bias=0x9b374)`.
- **Register-file = x24** (mảng slot 8B trên stack). op18 LOAD `x25=bits[7:10]→ldr [x24,x25*8]`. op42 STORE `regfile[dst][int16_off]=regfile[src]` (`ldr w,[PC],#4` PC+=4). Operand **rải-bit** (bfxil/and/orr) = obfuscation.
- **Native call DUY NHẤT @0x5594c `blr x8`** (0 blr khác, 0 bl-crypto trực tiếp). Kích hoạt bởi cờ `@0x55880 b.eq 0x55934`. Gọi `x8=*(*[sp+0x38])`, arg `x0=*[sp+0x28]`. Entry set [sp+0x38]→(*=x1 input), [sp+0x28]→(*=x2 tableA); các slot này **alias register-file x24** nên đích/arg tính ĐỘNG lúc chạy.

**tableA(6)/tableB(8) @0x1e0530/0x1e0560:** R_AARCH64_RELATIVE (type 1027), addend = con trỏ **computed-space** (0x5ce0a8,0x56ccXX,0x5153XX — vượt max VMA 0x1fe1e0), giống `table_ptr=0x6b5fe0`. Cần wrap-K để về .text (window K∈[−0x4e6554,−0x453b08] tồn tại, chưa duy nhất từ "land in .text"). Là **vtable/native-fn table** interpreter giải mã lúc entry.

**PROGRAM 0x191f40 = 875 lệnh, 20 opcode.** 6 opcode nóng = 94%: op44(325 rotate-reg), op42 STORE(190), op18 LOAD(190), op38(70), op1(27), op15(25). Hình dạng: header op38 + 10 STORE init(tag 0xef) + copy loop LOAD field[i]→STORE out[off](tag 0xe8/0xe9).

**⇒ ĐƯỜNG OFFLINE DUY NHẤT = VIẾT EMULATOR VM** port ~20 handler (đọc ARM64 từng cái) + register-file + native-dispatch + giải computed-pointer. Bounded nhưng build lớn/dễ sai, verify chỉ 1 oracle (slot16 device-7666 `0368525bbc8948577a33284cac9c660d`). Không có unicorn/capstone ⇒ port tay.
**Việc còn lại (đã scope):** (1) full-disasm 875 lệnh với operand-decode đúng; (2) port handler 18/42/44/38/1/15 (94%) rồi phần đuôi; (3) giải wrap-K + map native fn; (4) chạy → khớp slot16.

## 14. EMULATOR CHẠY THẬT (unicorn) + obfuscation ĐỒNG NHẤT + keva-store = runtime-state [MILESTONE 2]
**Đảo chiều tooling (sửa §12/§13 "không có unicorn"):** MẠNG CÓ → cài `.venv-emu` (unicorn 2.1.4 + capstone 5.0.7). ⇒ KHÔNG port tay 20 handler nữa — **emulate machine-code thật**.
- `_vm_emu.py` = harness: map 2 PT_LOAD, áp RELATIVE reloc (1027: `*(off)=BASE+addend`), wire 165 PLT stub (STUB_BASE=0x05000000), bump-alloc (HEAP 0x10000000), stub malloc/memcpy/memset/memcmp/strlen…, lazy-map unmapped, hook code.
- `_emu_run_F.py`: chạy `e.call(0x52924,[PROG=0x191f40,IN,TABA=0x1e0530,TABB=0x1e0560,OUT])`.
- **KẾT QUẢ:** F chạy tới hết **76794 lệnh**, **40 native-call @0x5594c**, đích = **0x13a60c..0x13a714** (cụm cạnh 0x13a834). Delta đích KHỚP delta tableB ⇒ **wrap-K tableB = −0x3dad48** (0x13a60c−0x515354), unicorn **tự áp** (marshaller tự tính). Marker input ⇒ trap 0x5d480, 0 ghi OUT.

**Bản chất object-graph (đọc hàm cha 0x13848c, prologue `stp x28,x19`):**
```
obj[0]=x0  obj[8]=x1  obj[0x10]=x2   ← 3 arg C++ hàm cha (device-context objects)
obj[0x18]=0x13a834 (native trampoline: mov x2,x0;mov x0,x1;br x2)
obj[0x20]=sp+0x6e0 (scratch)  obj[0x28]=x30=0x1384e8 (return-addr, vào f(x30) decode)
```
x4=OUT=sp+0x20=slot16(16B). Sau `bl F` hàm cha **BỎ QUA sp+0x20** ⇒ slot16 thật ghi NGƯỢC vào x0/x1/x2 (0x13a60c: `str x0,[x19,#8]`). Cụm 0x13a6xx = **closure/vtable-thunk C++** (`ldr x8,[x0]; blr x8`) — crypto nằm trong **method ảo** của x0/x1/x2. 0x13848c CHỈ 1 occurrence, 0 data-ptr ⇒ gọi qua dispatch (VM lồng tầng).

**OBFUSCATION = MỘT CÔNG THỨC (crack xong):** mọi computed-pointer = `real = computed_base + f(self_addr)`:
- f(x)=`((C11|~x)&C12) + ((x&C9)|C10)) ^ C13`; C9=0x104_00040400, C10=0x01010104, C11=0xa060400a021040, C12=0xa061440a061440. **C13 biến-thể per-callsite** (dispatch=0xff5f9ebbf4b521ec; keva 0x11a64c=0xff5f9ebbf42a3b84).
- Bảng global (RELATIVE reloc, addend=computed-space): `*(0x1f00e0)=0x6b5fe0` (dispatch-table), `*(0x1f2e70)=0xf28bd0`/`*(0x1f2e68)=0xf28bd8` (keva registry). VD: `0xf28bd0 + f(0x11a64c) = 0x1fba90` ✅ in-range.
- **0 init_array ctor** (`.init_array`@0x1d4f88 sz0x498 nhưng 0 reloc RELATIVE trỏ vào) ⇒ KHÔNG cần chạy init để giải pointer.

**NÚT THẮT THẬT (định tính lại):** keva-store tại vùng ~0x1fba90 = **.bss zero-init** (.bss 0x1efc20..0x1fa1e0, maxvma 0x1fe1e0). Device data (psk/ecneuq/semithc/wayval/device_id) là **runtime-state nạp lúc device-register**, KHÔNG có trong .so tĩnh. keva-get 0x11a64c gọi với **key-ID số** (root-fn dùng w0=0x10003). slot16 phụ thuộc nội dung keva-store ⇒
**⇒ ĐƯỜNG OFFLINE (bounded, cụ thể):** (1) map key-ID→field (0x10003=?…); (2) **stub keva-get trả giá trị device-7666**; (3) emulate producer (0x13848c hoặc cao hơn) với x0/x1/x2 tối thiểu + keva-stub; (4) KDF thật chạy → đọc slot16 → khớp `0368525bbc8948577a33284cac9c660d`. Iterative: chạy→thấy thiếu gì→cấp stub→lặp.
**Tools mới:** `_vm_emu.py`, `_emu_run_F.py` (huongB_devirt19/). Env `.venv-emu`.

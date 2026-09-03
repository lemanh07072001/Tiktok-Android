# 50 — VM 0x55950 dispatch: giải phẫu TĨNH (objdump, zero-môi-trường)

**Ngày:** 2026-08-27 · **AI:** claude · **Nguồn:** `huongB_devirt19/bin/libmetasec_ov.so`
(ELF aarch64, stripped, 2032384 B, BuildID `5a2f793c…`). **Công cụ:** `/usr/bin/objdump` (llvm). KHÔNG cần emulator/frida/mạng — lặp lại được bởi bất kỳ ai.

> Bối cảnh: session này MẤT môi trường live (emulator tắt, venv `fenv` bị wipe, `import frida` fail, **pip cache KHÔNG có capstone/frida-core wheel** ⇒ frida không cài offline được). Nên chuyển sang **static disasm** — vừa bền vững vừa đúng bản chất devirt. Kết quả dưới đây xác nhận ĐỘC LẬP (bằng ELF tĩnh) đúng bức tường mà notes 39/42/49 chạm bằng dynamic.

## 1. Dispatcher preamble @ 0x55950 (xác nhận convention TĨNH)
```
55950: ldr  x8,[x23]         ; x8 = *x23 = bytecode pointer (bcp)
5595c: adrp x30,0x52000
55960: add  x30,x30,#0x924   ; LR = 0x52924  (interp loop — khớp note39 "interp 0x52924")
55964: adrp x7,0x1f0000      ; x7 = 0x1f0000  (VM control-block trong .data)
55968: add  x8,x8,#0x4       ; opcode word @ bcp+4   ✓ convention đúng
5596c: b    0x55890          ; → dispatch tail (SHARED)
```
→ Xác nhận tĩnh: `x23`=con trỏ-tới-bcp, `x24`=regfile, opcode word tại `bcp+4`.
Mỗi handler có **preamble riêng** nạp `x30` bằng adrp+add **hằng số riêng** (vd 0x52924) — con số này KHÔNG phải return address, mà là **khóa ngữ cảnh** đưa vào dispatch (xem §2).

## 2. Dispatch tail @ 0x55890 (LÕI — số học dispatch đầy đủ)
```
558b4: str  x8,[x23]              ; *x23 = bcp mới (advance)
558d4: ldr  w8,[x8]               ; w8 = opcode word tại bcp
558f8: and  x8,x8,#0x3f           ; opcode = word & 0x3f      ✓ 6-bit (max 64)
558dc: ldr  x10,[x7,#0xe0]        ; table_base = *(0x1f00e0)   ← con trỏ RUNTIME
   ; --- obfuscation: offset phụ-thuộc-ngữ-cảnh từ x30 ---
558c8: and  x9, x30, #<c9>
558e0: orn  x11,x11,x30
558e8: and  x11,x11,#<c12>
558f0: add  x9, x11, x9
558f4: eor  x9, x9, #<c13>        ; x9 = f(x30)  (chọn "context sub-table")
558fc: add  x9, x10, x9           ; x9 = table_base + f(x30)
55900: add  x8, x9, x8, lsl #3    ; addr = table_base + f(x30) + opcode*8
55904: ldr  x8,[x8]               ; entry = ctx_table[opcode]  (con trỏ BIAS)
55908: ldur x9,[x29,#-0x58]       ; x9 = bias (lưu trên stack frame)
55918: sub  x15, x8, x9           ; x15 = de-bias → VA handler THẬT
55930: br   x15                   ; → nhảy handler
```

### Ý nghĩa (3 lớp hardening — thiết kế để chống lift tĩnh):
1. **Context-threaded dispatch:** index = `opcode*8 + f(x30)`. Vì `x30` do preamble *từng handler* nạp (hằng riêng), **cùng một opcode ánh xạ handler KHÁC nhau tùy handler tiền nhiệm**. Opcode KHÔNG ổn định toàn cục.
2. **Pointer biasing:** entry đọc từ bảng là con trỏ đã cộng bias; VA thật = `entry − [x29−0x58]`. Bias ở runtime-frame.
3. **Table base = con trỏ runtime** tại `.data+0xe0` (xem §3).

## 3. TƯỜNG static: bảng dispatch được materialize LÚC CHẠY
`.data` VMA 0x1f0000 (size 0x3c20) = VM control-block. Ô table-base:
```
reloc:  0x1f00e0  R_AARCH64_RELATIVE  *ABS*+0x6b5fe0
bytes:  1f00e0: e0 5f 6b 00 …   (=0x6b5fe0)
        1f00e8: e0 61 6b 00     (=0x6b61e0)   ← +0x200
        1f00f0: e0 63 6b 00     (=0x6b63e0)   ← +0x200
        1f00f8: 08 65 6b 00     (=0x6b6508)
```
- `0x6b5fe0 ≈ 7.04 MB` **> kích thước module ~2.09 MB** (hết .bss @ 0x1fe1e0). ⇒ **KHÔNG file-backed.** Giá trị reloc chỉ là **placeholder**; init-code ghi đè `[0x1f00e0]` bằng con trỏ heap/mmap thật lúc chạy.
- Các con trỏ cách đều **0x200 = 64 opcode × 8B** ⇒ mỗi "context" một bảng 64-entry; nhiều context (0x6b5fe0, …61e0, …63e0, …6508). Khớp §2 (f(x30) chọn context).

**~~Kết luận~~ (SAI — xem §7):** ~~handler hot-path nằm trong vùng dựng lúc chạy, enumerate từ file BẤT KHẢ.~~
> ⛔ **§3 này BỊ SUPERSEDE bởi §7.** Sai lầm: đọc thiếu phần số học của dispatch. `0x6b5fe0` KHÔNG phải con trỏ runtime — nó là 1 hạng tử; cộng `f(x30)` (hằng 64-bit) **wrap mod 2^64** ra VMA thật **TRONG file**. Bảng dispatch nằm TĨNH trong `.data.rel.ro`. Xem §7.

### Đối chiếu: có tồn tại handler TĨNH (thunk) trong file
`.data 0x1f0020..0x1f00c8` chứa nhóm **getter-thunk** trỏ .text (VD 0x504cc):
```
504cc: adrp x0,0x50000; add x0,#0x4fc; ret   → trả 0x504fc (prologue hàm thật)
504d8: → 0x51274 ; 504e4: → 0x513a0 ; 504f0: → 0x52030   (nhóm +0xc)
0x52ecc8.. (10 thunk +0xc) ; 0x119918 ; …
```
Một số opcode "lạnh" resolve qua các thunk TĨNH này ⇒ **lift được từ file**. Nhưng op nóng crypto (op40) đi qua bảng runtime §3.

## 4. Đã loại (red-herring)
- `0x51004 str x10,[x19,#0xe0]` **KHÔNG phải** builder table-base: đó là move `std::vector`-like trên object heap `[x19]` (copy struct 4 con trỏ 0xc8/0xd0/0xd8/0xe0). x19≠0x1f0000.

## 5. BƯỚC STATIC KẾ (offline, không cần môi trường)
Tìm **builder** ghi `[0x1f00e0]` con trỏ mmap thật trong số **157 site `adrp …,0x1f0000`** (`_disasm_full.txt` đã dump). Builder này khả năng cao:
1. `mmap`/allocator vùng RWX (~vài chục KB, ≥4 context × 0x200),
2. **giải mã/copy** thân handler từ dữ liệu file (`.rodata`/`.data.rel.ro`) vào vùng đó,
3. ghi con trỏ vùng → `[0x1f00e0]`.
Nếu (2) là **copy/giải-mã từ file** ⇒ khôi phục handler TĨNH được (crack tường mà KHÔNG cần frida). Nếu là JIT-emit thuần ⇒ vẫn cần một lần **dump runtime** (cần khôi phục emulator+frida, hiện DOWN).

**Anchor:** `.init_array` @ 0x1d8f88 (18+ ctor: 0x11a9d4, 0x30e00, 0x30ff4, …). Builder VM nằm trong chuỗi ctor hoặc nhánh JNI_OnLoad @ 0x4dda0.

## 6. Trạng thái deliverable (KHÔNG đổi)
- **no-phone login KHẢ THI NGAY** qua **AVD-attestation + offline signer** (#19 verified 11/11 bit-exact — đã bank). Producer chỉ phục vụ "pure-node zero-device".
- Producer vẫn **OFF critical path** (ec7 = Play-Integrity-gated, độc lập slot16 — human đã bảo bỏ qua ec7).
- Fork còn lại để tới op40: **(A)** reverse builder §5 offline (bền, chậm, có thể vẫn cần 1 dump runtime); **(B)** khôi phục môi trường (cần mạng/emulator của human) → dump bảng runtime rồi lift nhanh hơn; **(C)** chốt AVD-hybrid đã proven.

---

## 7. ★ BREAKTHROUGH — bảng dispatch NẰM TĨNH TRONG FILE (đính chính §3)

§3 kết luận sai vì đọc thiếu số học. Giải đủ dispatch tail:
```
table_ptr = *(0x1f00e0)                                  # =0x6b5fe0 (static, base=0)
f(x30)    = (((x30 & c9)|c10) + ((c11|~x30) & c12)) ^ c13    # mod 2^64, hằng 64-bit
base      = (table_ptr + f(x30)) & (2^64-1)              # WRAP → VMA thật
entry(op) = *(base + op*8)                                # con trỏ handler .text
handler   = entry - [x29-0x58]                            # bias runtime; static bias=0
```
**Hằng số (từ movk @0x55890..0x558f4):**
`c9=0x0000010400040400  c10=0x01010104  c11=0x00a060400a021040  c12=0x00a061440a061440  c13=0xff5f9ebbf4b521ec`

**Kiểm chứng với x30=0x52924** (context của preamble @0x55950):
`f(x30)=0xffffffffffb234a8 (= −0x4dcb58) → base = 0x6b5fe0 − 0x4dcb58 = 0x1d9488` ✓ **TRONG .data.rel.ro** (0x1d9430..0x1eeb90).
`0x6b5fe0` + các hằng khổng lồ = **obfuscation số học triệt-tiêu-qua-tràn**, KHÔNG phải con trỏ runtime.

**Bảng @0x1d9488 giải mã trọn (47 handler thật + trap 0xf87d8×17), tất cả trong .text 0xedec0..0xf8070:**
```
op1→0f488c op3→0f34bc op4→0f52fc op5→0f5544 op6→0f6914 op7→0f56c4 op8→0f5720 op9→0f44bc
op12→0f2958 op13→0f6f2c op15→0f4a88 op17→0f50b8 op18→0f60a0 op19→0f4c98 op20→0f6454
op22→0f76b8 op23→0f5e94 op24→0f8070 op25→0f66f8 op26→0f62a8 op28→0f7e34 op30→0f40e0
op33→0f4f68 op36→0f5348 op37→0f4db0 op38→0f3dc8 op40→0f6b58 op41→0f55c0 op42→0f7470
op43→0f79f0 op44→0edec0 op45→0f1ff8 op46→0f6a34 op47→0f5c8c op48→0f46c0 op49→0f780c
op50→0f7c04 op52→0f7288 op53→0f58c8 op54→0f5128 op55→0f42b8 op56→0f3f2c op57→0f7090
op59→0f7584 op60→0f5a38 op61→0f5d74 op63→0f6d24
```

**Engine = direct-threaded (không phải re-dispatch qua 0x55950 mỗi op):** handler dùng `x1`=regfile (idx*8), `x0`=con trỏ node IR (mỗi node 0x20B), cuối handler `ldr x4,[x0,#0x20]!; br x4` = nhảy thẳng handler node kế. VD op3/op9 = "zero regfile[idx]; advance".

### op40 (0xf6b58) — KHÔNG phải ARX; là MARSHAL có bảng
Body thật @0xf75d4:
```
ldrh w9,[x8,#2]; ldrb w11,[x8,#8]; ldrb w10,[x8]
x12 += w9<<5;  x12 += w11<<4;  x12 = *(x12 + w10<<3)   # gather từ bảng descriptor
str x12,[x26]                                          # ghi output
```
Bảng hằng op40 tham chiếu (0x1dd000/0x1de/0x1df trong .data.rel.ro) = **mảng con trỏ .text** (0xd5ed0, 0x77e44, 0x78568 lặp) = **descriptor serialize field (protobuf-like)**, KHÔNG phải S-box. ⇒ Context x30=0x52924 = **VM serialize message** (nên op40 ~50% histogram: mỗi field 1 lần). **Slot16-ARX ở context KHÁC (x30 khác).**

### Ý nghĩa & bước kế
- Phương pháp decode tĩnh **hoạt động cho MỌI context** — chỉ đổi x30. Tool tái sử dụng: `huongB_devirt19/_vm_static_decode.py` (đã bank, verify được).
- **BƯỚC KẾ:** liệt kê các preamble handler (mỗi cái `adrp x30,...; add x30,#imm` nạp x30 riêng) → tập context x30 khả dĩ → decode context nào có handler **ARX** (ror/eor/add trên word 32-bit + ratchet buffer regfile[29], note39) = **context slot16-crypto**. Rồi lift từng op ARX → điền `p3_offline_signer._execute_op` → verify bit-exact vs `_clean_tuples`/hash19.
- **KHÔNG còn cần frida/emulator cho bước enumerate** — tường JIT là ảo. (Có thể cần 1 dump runtime chỉ để xác nhận bytecode-stream + x30 thực tế của slot16, nhưng cấu trúc handler đã lift được offline.)

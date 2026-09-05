# Note 59 — Devirt pskVersion gate: tiến độ (2026-09-03, session-6)

> 🔁 **SUPERSEDED-BY note 61 (audit 2026-09-04):** header note đã tự defer sang 61 (handoff sạch). Mislabel nội bộ sửa sau: 0x154f7c = byte-append primitive, KHÔNG phải schema-serializer (note 60 A2); op44=0xedec0 phantom, thật = 0x52b4c sau bias −0x9b374 (note 61 §1b); 'devirt VM = đường duy nhất' bị notes 60/63 thay (native serializer + injection). Giữ làm derivation log thô.

> 📌 SUMMARY SẠCH + HANDOFF: [note 61](61-state-handoff-vm-and-widevine.md). File này là append-log chi tiết.

> Mục tiêu (user chốt): full-772 register, OFFLINE-KHÔNG-PHONE. Đường duy nhất = devirt VM để ép `pskVersion="0"` → #16/#18/#19 mọc.
> Chấp nhận đây là dự án nhiều-tuần/nhiều-session. Note này track tiến độ để session sau tiếp.

## Phase 0 — canh môi trường + xác nhận tường (DONE)
- **.so ALIGNED**: `signer/native/libmetasec_ov.so` == `huongB_devirt19/bin/libmetasec_ov.so` == phone = **sha256 c06892e3…, 2032384B**. Ghidra project (tt.rep, image base 0x100000) và tt.Dump dùng CÙNG .so → **offset khớp 100%**, các địa chỉ note 36/46 transfer được sang tt.Dump (sau khi map version).
- **tt.Dump ĐÃ QUA cổng init**: nó sinh X-Argus 408 → KHÔNG kẹt "SDK not init". ⇒ tường note 46 (init-flag = getuid-syscall via wrapper `0x16c170(0x197)`, gate `cmp #0x40c` @0x16ca84) là của **harness khác** (unidbg MSB_*), KHÔNG phải tt.Dump. Đừng đuổi init-flag cho tt.Dump.
- **Tường THẬT của tt.Dump = gate-2: quyết định `pskVersion` trong VM `0x52924`** → nếu "none" thì bỏ #16/#18/#19/#32 (→408); nếu "0" thì dựng đủ (→772). note 36-2A B1 đã chứng minh: quyết định ở **mức VM-bytecode, KHÔNG phải 1 biến .data** (patch 108 candidate + read-watch 801-read đều FAIL) → chỉ còn **devirt VM**.
- **Chuỗi pskVer verified trên .so c06892e3** (đều là code hợp lệ): `0x8e2e8 → 0x95a3c → VM 0x52924 → 0x9bb50 → 0x154f7c`. `0x154f7c` = **FUN_00254f24 = serializer protobuf schema-driven** (lặp field, wire-type switch, descriptor 0x48B/field) — nơi GHI report; "none"/"0" quyết upstream.
- Syscall wrapper trên .so này = **`0x16c170`**: `syscall(id − 0xe9, args...)`. init-flag `DAT_002fcfa0`(file 0x1fcfa0) = `0x16c170(0x197)` = syscall(174)=getuid.

## Tường đã loại trừ (đừng lặp — note 36/46)
- Patch init-flag=0x40c (MSB_INITFLAG) → SIGN chạy nhưng #16/#18/#19 VẮNG (gate-2 vẫn chặn).
- Feed device-state THẬT (device 7666 + triplet) vào unidbg → vẫn "none" (E1-E5). unidbg KHÔNG execute nổi VM PSK-provisioning (Wall 1).
- Inject KMS cache (.mss_9b8e) → metasec re-eval runtime, bỏ cache.
- Native read-watch/patch biến đơn → FAIL (VM-bytecode-level).

## Roadmap devirt (nhiều-session) — theo notes 42/50/52 (VM anatomy)
1. **[đang] Bản đồ VM 0x52924**: dispatch, opcode table, handler set. note 50 (VM-dispatch-STATIC-anatomy) + note 52 (VM-PROGRAM-MAP) có sẵn — đọc + tái lập trên .so c06892e3.
2. **Trace VM execution trong tt.Dump** quanh window `0x95a3c→0x154f7c`: log opcode-stream + state-read (base-relative, gated theo window — sửa lỗi absolute cũ). Mục tiêu: tìm bytecode-instr rẽ nhánh "none" vs "0".
3. **Differential vs phone (oracle)**: phone 0x9ecc0→792 lấy nhánh "0". Hook/Stalker VM 0x52924 trên phone tại điểm quyết → lấy value nhánh "0". So với unidbg.
4. **Ép nhánh "0"**: patch VM-bytecode HOẶC set state VM cần. Verify #18/#19 mọc + so `_clean_tuples.json`.
5. **slot16≠0 (register)**: producer localized `0xa0748` (note 53) — lift 17-entry table @0x1f3688 (note 51). Ghép compute_hash19 với slot16 thật.
6. **#34/#35/#36 sig-parts**: RE thuật toán (note 30: sig per-request ký trên device-state, keyed dyn_seed). CHƯA có công thức — cần lift.

## Kill-criteria (note 36-2A): nếu 2 milestone liên tiếp chỉ lộ "tầng VM sâu hơn" mà không gần pskVersion="0"/slot16 → DỪNG, báo user, cân nhắc chi phí vs A2(capture — user đã loại).

## Trạng thái: Phase 0 DONE. Phase 1 (bản đồ VM 0x52924) = bước tiếp. Encoder/outer-key/#19-hash/#24 ĐÃ GIẢI (note 58) — chỉ thiếu pskVersion-gate + slot16≠0 + #34-36 để ghép full-772 offline.

## Phase 1 — VM anatomy mapped (DONE, agent digest notes 39/42/50/52)
- **VM = threaded-code, interp `0x52924`**, dispatch preamble `0x55950`, tail `0x55890`. Regs: **x23=&bcp, x24=regfile(32), x7=ctrl-block 0x1f0000, x30=context-key (KHÔNG phải return addr)**, opcode=word&0x3f (6-bit), IR-node 0x20B.
- **Handler table** cho context x30=0x52924 = VMA **`0x1d9488`** (47 handler thật + 17 trap), static-decodable qua arithmetic (`_vm_static_decode.py`). Bias handler `-0x9b374`. Bytecode blob `0x17bbf0..0x196000` **self-decrypt + operand XOR key `0x6a9091b9`** → phải đọc ở trạng thái đã giải mã.
- **Report-builder VM call = `0x95a3c`**: `FUN_00152924(prog=&DAT_002814f0=0x1814f0, ctx, tbl 0x1db360, tbl2 0x1db430, state)`. (Lưu ý: agent nói 0x1814f0 = SM3-hash orchestrator; serializer field-emit ở context op40 marshaller — cần chốt program nào chứa nhánh pskVersion.)
- Quyết định emit #18/#19 = **op44 (computed-branch, handler 0xedec0) / op18 (0x5ad2c)** so 1 regfile-slot (cờ pskVersion) trong bytecode đã-giải-mã.
- **Tooling sẵn**: `_vm_static_decode.py` (decode table any-context, offline), `_vmprogs.py` (35-program map), `_vm_lifter.py`, `_vm_unicorn_replay.py` (BIT-EXACT proven trên SM3 `0x186420`), `_vm_trace600.js` (Stalker 1-invocation), `_dumpmem.sh` (passive /proc/mem dump).

## ★★ PHÁT HIỆN QUYẾT ĐỊNH (chốt của notes, agent xác nhận):
**slot16 GIÁ TRỊ THẬT của device = KHÔNG thể tái tạo offline nếu không có 1 lần capture q2** (PSK-material 64B object trong object-graph runtime; SHA/AES/MD5/SM3/Simon/Speck/TEA battery đều FAIL trên `mat`; giải q2 từ 13 I/O = one-way-infeasible — note 52 CHỐT). ⇒ full-772-register với slot16 ĐÚNG-của-device, **KHÔNG-phone-BAO-GIỜ = BẤT KHẢ THI (đã chứng minh)**.

## ⇒ Chia 2 nghĩa "correct 772" — QUYẾT ĐỊNH có làm tiếp được không:
- **(A) 772 đúng-cấu-trúc, giá trị tự-nhất-quán-synthetic** (bỏ trust): slot16 tự chọn → #19=SM3(query‖slot16‖'0') tự-nhất-quán; #18 synthetic; ép pskVersion="0" bằng **patch nhánh VM bytecode** → SDK emit đủ report (#34-36 do SDK tự tính) → encode → 772. **KHẢ THI qua Phase 2 (patch VM branch).**
- **(B) 772 khớp device THẬT (server dùng được)**: cần slot16 thật → cần q2 capture → **BẤT KHẢ THI offline-no-phone** (proven).

## Phase 2 (next) = patch nhánh pskVersion trong bytecode để ép "0" (chỉ có nghĩa nếu (A)):
1. `_vm_static_decode.py` dump program report-builder (XOR 0x6a9091b9), tìm op44 gating #18/#19.
2. Trace VM trong tt.Dump (tôi control) tại report-builder → lấy regfile-value nhánh.
3. Patch bytecode operand/branch ép "0" → tt.Dump emit report 772-struct.
4. Verify bằng `_vm_unicorn_replay.py` (bit-exact-proven).

## Phase 2 — localized pskVersion decision (DONE, session-6)
- **Trace VM interp 0x52924 trong sign tt.Dump** (hook x0=program): 11 program distinct — chủ yếu SM3-cluster (0x186420 ×16 compression, 0x1864f0/0x186600 ×4 IV, 0x17f940/0x18fa80/0x190140 ratchet) + marshaller (0x18f430/0x191f40/0x184780 ×1) + **0x1814f0 ×1 (orchestrator)**. KHÔNG có program serializer riêng ⇒ pskVersion quyết UPSTREAM, trước collection #18/#19 (nên bị skip → 408).
- **`0x8e2e8` = wrapper mỏng**: chỉ `FUN_00195a3c(*param_1)` (=0x95a3c) + bounds-check. Không phải điểm quyết.
- **`0x95a3c`**: `FUN_00152924(prog=0x1814f0, ctx, tbl 0x1db360/0x1db430, state)` — chạy VM prog **0x1814f0** (report-hash orchestrator, 23 native call-outs).
- **`0x9bb50` = FUN_0019bb3c** = native-callout invoker: `ret=(*(code*)*p)(p[1],p[2]); p[3]=ret`. VM prog 0x1814f0 gọi native qua đây.
- ⇒ **Quyết định pskVersion="none"/"0" nằm TRONG VM prog 0x1814f0**, thực hiện qua 1 trong 23 native-callout (0x9bb50). unidbg chạy prog này (thấy trong trace) nhưng ra "none" vì callout kiểm PSK-state trả "chưa provision".

## Phase 3 (next, multi-session) = tìm + ép callout quyết pskVersion
1. Trace VM prog 0x1814f0 trong tt.Dump: log MỖI native-callout qua 0x9bb50 (target fn + args + ret). Tìm callout mà ret quyết "none" vs "0" (so path tt.Dump[none] vs phone[0]).
2. Ép callout đó trả giá trị "0"-path trong tt.Dump → xem report có mọc #18/#19 + pskVersion="0" không.
3. Nếu mọc: kết hợp captured q2/slot16 (phone-support 1 lần) → register-772 offline. Verify vs genuine.
4. Nếu callout cần PSK-state runtime unidbg không dựng nổi → lift callout đó (native RE) hoặc feed captured PSK object.

## Ghi chú kiến trúc (user chốt): phone dùng 1-LẦN hỗ trợ (hút q2/slot16/state) → offline mãi. Prior "2135" thực ra dùng METASEC_ORACLE (phone per-request) hoặc login-thin — register-772-offline-genuine CHƯA dựng = đang làm (đường VM-devirt).

## Tiến độ tổng: Phase 0/1/2 DONE. Phase 3 (trace 23 callouts of prog 0x1814f0) = multi-session. Tooling: tt.Dump (control được), _vm_unicorn_replay.py (verify), phone-oracle (differential + capture q2).

## Phase 3 — bắt đầu, xác nhận tường VM-bytecode (session-6)
- Probe 1: hook invoker `0x9bb50` trong sign tt.Dump → **0 call**. ⇒ callout VM KHÔNG qua 0x9bb50 trong path này (0x9bb50 ở SAU VM, không phải invoker chung — threaded VM gọi native trực tiếp trong handler).
- Probe 2: search `"none"` (giá trị pskVersion) plaintext trong .so → **0 hit** (cả xref). ⇒ string bị **obfuscate** (decode runtime qua MS.a(0x1000001)) — không tìm được điểm ghi bằng static string-xref.
- ⇒ **Khớp note 36 B1**: quyết định pskVersion = VM-bytecode-level + string mã hoá. Probe native đơn giản KHÔNG isolate được (đúng như B1 đã kết luận sau khi thử 108 candidate + 801 read-watch).
- **Phase 3 thật = lift VM bytecode** (multi-week core): dump bytecode ĐÃ-GIẢI-MÃ của prog 0x1814f0 từ RAM (tt.Dump control được — hook interp khi prog=0x1814f0, dump vùng [x23] đọc) → lift bằng `_vm_lifter.py`/`_vm_static_decode.py` → tìm op44/op18 branch quyết pskVersion (so path emit-#18/#19 vs skip) → patch bytecode operand ép "0" → verify `_vm_unicorn_replay.py`.
- Alternative differential: hook interp 0x52924 trên PHONE (nhánh "0") vs tt.Dump (nhánh "none") tại cùng prog 0x1814f0 → so opcode-stream, điểm rẽ đầu tiên = branch quyết. Cần _vm_trace600.js-style Stalker (note 42 — bounded 1-invocation OK).

## CHECKPOINT session-6: Phase 0/1/2 DONE + Phase 3 khởi động (xác nhận = VM-bytecode lift, multi-week).
## State đầy đủ trong note 59 + BOARD. Session sau nối tiếp: dump decrypted bytecode prog 0x1814f0 → lift → tìm+patch pskVersion branch.

## Phase 3 SETUP COMPLETE (session-6 end) — lift viable + tooled
- **Bytecode = static** (RAM==file 512/512 @0x1814f0): KHÔNG blob-encrypt, chỉ operand XOR key 0x6a9091b9 (tooling xử lý). Prog 0x1814f0 dumped → /tmp/bc_1814f0_ram.bin.
- **Handler table context report-builder (x30=0x52924) DECODED** (`_vm_static_decode.py` chạy OK) → ground-truth/vm_handler_table_52924.txt: 47 handler. Chốt: **op44(0x2c)→0xedec0 (computed-branch)**, op18(0x12)→0xf60a0, op40(0x28)→0xf6b58 (field-marshaller), op44 = ứng viên nhánh gating #18/#19.
- **Setup xong hoàn toàn**: VM mapped + handler table decoded + target prog (0x1814f0) identified+dumped + tooling (_vm_static_decode.py OK, _vm_lifter.py/_vm_unicorn_replay.py sẵn) + venv (.venv-emu capstone 5.0.7).

## BƯỚC TIẾP (multi-session core, đã tooled — không còn tường mù):
1. Lift prog 0x1814f0 bytecode → opcode-stream (dùng handler table trên + XOR-decode operand).
2. Tìm op44/op18 branch quyết pskVersion (path emit-#18/#19 vs skip). Cross-check differential phone(0) vs tt.Dump(none).
3. Patch bytecode operand/branch ép "0" trong tt.Dump → verify report mọc #18/#19.
4. Ghép captured q2/slot16 (phone-support 1 lần) → register-772 offline server-nhận.

## KẾT SESSION-6: devirt Phase 0/1/2/3-setup DONE. Không còn "tường mù" — là task lift bytecode có bản đồ đầy đủ. Note 59 = state nối tiếp.

## Phase 3 — lift bytecode: xác định công cụ còn thiếu (session-6 end)
- Kiểm tra `_vm_disasm.py` = disasm NATIVE dispatcher 0x55950 (không phải bytecode-program). `_vm_static_decode.py` = decode handler-TABLE. `_vm_lift.py`/`_vm_lifter.py` = reconstruct reg-evolution từ DYNAMIC trace (note 42). **KHÔNG có bytecode-PROGRAM disassembler** (parse IR-node của 1 program → opcode-stream).
- ⇒ Bước lift prog 0x1814f0 cần 1 trong 2 (đều là core-work):
  - **(a) Static**: VIẾT bytecode-disassembler — reverse IR-node format (note 50: node 0x20B, advance [x0,#0x20]!, opcode=word&0x3f, operand bit-scatter XOR 0x6a9091b9). Parse prog 0x1814f0 (/tmp/bc_1814f0_ram.bin) → opcode-stream → tìm op44 branch.
  - **(b) Dynamic**: trace VM trong tt.Dump (control được) — hook mỗi handler-entry (từ vm_handler_table_52924.txt) log opcode+regfile-delta → feed `_vm_lift.py` → reconstruct → tìm branch. Cross-check differential phone(0)/tt.Dump(none).
- Cả 2 = focused multi-session work. Setup đã đủ (handler-table, bytecode dump, tooling, venv).

## KẾT SESSION-6 (chốt thật): devirt Phase 0/1/2/3-SETUP done. Bytecode-program disassembler CHƯA có = việc lift chính (multi-week). State đầy đủ note 59 để phiên sau viết disassembler HOẶC dynamic-trace-lift.

## Phase 3 — REFINE: pskVersion emit-decision KHÔNG ở VM context x30=0x52924 (session-6 end)
- Hook op44(0xedec0)/op18(0xf60a0) [handler context x30=0x52924] trong sign tt.Dump → **0 hit** (chỉ 37 PROG-marker = 36 prog-invocation crypto). ⇒ **context report-serializer x30=0x52924 KHÔNG execute trong sign**. VM prog chạy (0x186420 SM3 ×16, v.v.) dùng context KHÁC (crypto).
- ⇒ **Report dựng NATIVE** (0x154f7c = FUN_00254f24 schema-serializer) + field crypto/hash từ VM. Quyết định emit-#18/#19 nhiều khả năng = **NATIVE branch kiểm state-flag** (quanh 0x95a3c / caller 0x8e2e8 / report-assembly), KHÔNG phải VM op44 như giả định agent. (note 36 B1 "VM-bytecode-level" có thể về slot16-crypto, không phải emit-decision.)
- **REDIRECT hướng lift (tractable hơn devirt VM)**: hunt NATIVE emit-decision:
  1. Trong tt.Dump, hook 0x154f7c (serializer FUN_00254f24) — nó lặp field theo descriptor; tìm field #18/#19/#20 descriptor + điều kiện skip. Descriptor table @0x1db360/0x1db430 (param của VM call 0x95a3c).
  2. HOẶC dump report struct trước serialize (hook Simon-encrypt input) → xác nhận field nào vắng → trace native code set field đó.
  3. Tìm native branch (cmp + b.cond) quyết include/skip #18/#19 dựa state-flag → patch flag/branch trong tt.Dump.
- Đây tractable hơn VM-bytecode-lift (native, decompile-able bằng Ghidra).

## KẾT SESSION-6 (chốt): devirt Phase 0/1/2 done + Phase 3 REFINED (emit-decision = NATIVE, không phải VM-op44 context 52924). Next = hunt native emit-branch quanh serializer 0x154f7c + descriptor 0x1db360/0x1db430. State đầy đủ note 59.

## Phase 3 — STATIC-DEVIRT ĐỘT PHÁ (2026-09-03, session tiếp) ★★★
> Sửa giả định SAI của Phase 1/3 trước: "bytecode blob 0x17bbf0..0x196000 self-encrypt → phải dump RAM". **SAI.**

### PHÁT HIỆN 1 — bytecode VM là PLAINTEXT trong file (không self-encrypt)
- Test: mẫu `BYTECODE_HEX` (RAM-capture "call #1" trong `_vm_lifter.py`) tìm thấy **y hệt trong .so file @0x17c934**.
- Decode 35 program (kể cả report-builder **0x1814f0**) bằng `op=word&0x3f`: **valid-opcode-frac ≈ 0.97–1.00** cho TẤT CẢ (opcode ∈ handler-set ctx 0x52924 = {1,3,4,5,6,7,8,9,12,13,15,17,18,19,20,22,23,24,25,26,28,30,33,36,37,38,40,41,42,43,44,45,46,47,48,49,50,52,53,54,55,56,57,59,60,61,63}).
- "Rác tại 0x1814f0" ở lần trước = đọc nhầm (op38/42/44 ĐỀU hợp lệ; tôi tưởng chỉ tới op25). Prologue chung mọi prog = `[38,42,42,42,42,42,1,18,...]`.
- ⇒ **Devirt = bài toán TĨNH, KHÔNG cần RAM dump / tt.Dump / phone.** Chỉ operand bị XOR `0x6a9091b9`. Tool: `_lift1814f0.py` (mới).

### PHÁT HIỆN 2 — prog 0x1814f0 (report-builder) structure
- 1618 entry (0x1814f0..0x184780), **492 op44** (computed-branch handler 0xedec0) = CFF-flattened nặng.
- Operand op44 = selector (giá trị lặp 0x6aaf04d5/0x6a9b8595…), KHÔNG phải địa chỉ.
- **0 operand trỏ .text** ⇒ native call-out KHÔNG mã hoá trong bytecode; đến qua bảng `0x1db360`/`0x1db430` (đối số VM `FUN_00152924`).

### PHÁT HIỆN 3 — bảng call-out/string bị OBFUSCATE qua fake RELATIVE addend (tường kế tiếp)
- `0x1db360`/`0x1db430` = mảng qword, relocate bằng **R_AARCH64_RELATIVE (type 1027)** nhưng **addend = 0xbef2b0/0xb7dddf… VƯỢT module (max VMA 0x1fe1e0)** → không thể là con-trỏ file-backed.
- Toàn module: **1745 reloc có addend out-of-module** (89 trong 2 bảng VM + 1656 nơi khác) vs 5020 addend in-module hợp lệ. ⇒ **routine init runtime fix-up (giải mã) 1745 addend này** (kỹ thuật packer). Static muốn resolve bảng VM ⇒ phải reverse deobfuscator addend đó.

### Trạng thái + đường còn lại (tĩnh, tractable nhưng multi-day mỗi bước)
1. [DONE] bytecode plaintext + lift infra (`_lift1814f0.py`).
2. [NEXT] reverse **reloc-addend deobfuscator** (init routine fix-up 1745 addend) → resolve bảng 0x1db360/0x1db430 → biết 23 native call-out của prog 0x1814f0.
3. reverse op44 semantics (handler 0xedec0) + operand-selector → dựng CFG.
4. tìm callout/branch quyết pskVersion "none"↔"0" → patch ép "0".
- Payoff vẫn = **(A) synthetic-772** (note 59 §★★): slot16 THẬT vẫn cần **1 lần capture q2** phone ⇒ để server-nhận vẫn phải chạm phone 1 lần (= y hệt yêu cầu capture-once, rẻ hơn nhiều).

### Kill-criteria note 36-2A: milestone-1 (bytecode liftable tĩnh) = tiến bộ THẬT; nhưng tầng kế (addend-deobfuscator + op44 semantics) = "tầng VM sâu hơn". Đây là điểm go/no-go: C đạt được nhiều nhất (A) — vẫn cần 1 phone. Báo user quyết.

## Phase 3 — CHỐT session-6: note-36 address-map KHÔNG transfer sang c06892e3 sign-path
- Probe trong sign tt.Dump (0x9ecc0, .so c06892e3): `0x9bb50`=0 hit, `0x154f7c`=0 hit, op44/op18 context x30=0x52924 = 0 hit, `"none"` không-plaintext, 0x154f7c có 0 BL-caller (indirect). ⇒ **chuỗi 0x8e2e8→0x95a3c→0x9bb50→0x154f7c của note 36/36-2A là từ .so VERSION KHÁC**, không phải đường report-build/serialize thật trong c06892e3.
- Điều ĐÚNG trong c06892e3: `0x95a3c` gọi VM prog `0x1814f0` (chạy trong sign, ×1) — nhưng downstream (serialize/pskVersion) đi đường khác note 36.
- **Toolchain decoder/encoder (xargus_decode/encode.py, gmssl/SIMON) KHÔNG có trên Mac này** (import từ /e/tiktok_signer Windows) → không decode được report tt.Dump tại chỗ để soi field.
- ⇒ **Phase 3 thật cần**: RE MỚI đường sign 0x9ecc0 nội bộ trên c06892e3 (không dùng địa chỉ note-36) — trace call-graph 0x9ecc0 → report-build → Simon-encrypt → AES-CBC (0x159de4, note 36 outer-key setup) → tìm pskVersion/emit-decision THẬT. HOẶC dùng Windows toolchain (mobile/, /e/tiktok_signer) nơi encoder+decoder+captures đầy đủ.

## KẾT SESSION-6 (chốt thật, firm): Devirt setup (Phase 0/1/2) SOLID + Phase 3 xác định note-36 map không transfer → cần RE mới 0x9ecc0-internals-on-c06892e3 HOẶC Windows toolchain. Không thể shortcut bằng probe thêm trong session này. State đầy đủ note 59.

## ★★★ BREAKTHROUGH (session-6, đảo giả định): tt.Dump + FRESH STATE đã có pskVersion="0" + attestation
- Tìm report PLAINTEXT trong RAM tt.Dump @0x12533140 (scan magic 08d2a4808204 lúc AES-CBC 0x159d70 hit) → parse protobuf trực tiếp (KHÔNG cần decoder toolchain).
- **tt.Dump report (256B, → X-Argus 408) ĐÃ CÓ**: #1,2,3,4,6,7,9,10,12,13,14,15,**#18(uuid16 28de5b64...)**,**#19(req_hash 9db56bfb...)**,**#20 pskVersion="0"**,#21,#23,#25,#28-31,**#32**,#33,**#34/#35/#36 sig**. ⇒ **KHỐI ATTESTATION ĐÃ ĐẦY ĐỦ, pskVersion="0" (KHÔNG phải "none")**.
- **NGUYÊN NHÂN**: FRESH device-state (pull từ phone SAU khi svc wifi enable → online-refreshed .msp/keva) đã provision PSK → pskVersion="0". Các run/notes "none" trước dùng state cũ/thiếu. ⇒ **kiến trúc capture-once→offline của user ĐÚNG + đã hoạt động cho attestation**.
- **DEVIRT VM pskVersion = KHÔNG CẦN** (nó đã "0"). Bỏ Phase 3 VM-lift.
- **Gap thật (tt.Dump 306B → genuine 594B) = field THIẾU**: #5 device_id, #8 sdk-ver-str, #16 device_token, #17 ts, **#24 widevine (132B, lớn nhất)**, #26. Toàn identity/config — tractable.

## PHASE MỚI (thay VM-devirt): ĐIỀN #5/#8/#16/#17/#24/#26
1. **#24 widevine** (+132B, quan trọng nhất): note 46 = offline-regen qua MediaDrm.getPropertyByteArray trong unidbg (cần chạy collect-thread + serve JNI MediaDrm). tt.Dump harness đơn giản chưa chạy collect-thread → #24 vắng. Thêm: serve MediaDrm JNI + trigger collect.
2. **#5 device_id / #16 device_token**: field identity từ device đã-register. tt.Dump state (fresh_sync) có kiid/rtk2_ms nhưng #5/#16 vắng → state có thể là unregistered HOẶC field không được set. Điều tra: field #5/#16 lấy từ đâu (store key nào) → serve.
3. **#8/#17/#26**: config/ts — nhỏ, điền sau.
4. Verify: report đủ field → X-Argus tiến tới ~594/772.

## Tools mới session này: report-magic-scan trong tt.Dump (hook AES-CBC 0x159d70 → scan heap 0x12000000-0x12800000 magic 08d2a4808204 → dump plaintext report → parse). KHÔNG cần decoder toolchain. AES-CBC 0x159d70 CONFIRMED = sign final-encrypt trên c06892e3.

## Phase 3 — 2 MILESTONE THẬT + kill-criteria checkpoint (2026-09-03, claude, session tiếp)
### MILESTONE A: bytecode VM = PLAINTEXT trong file (đã ghi trên). Devirt = STATIC.
### MILESTONE B: deobfuscation transform của bảng con-trỏ VM = addend − 0xa00000
- Addend obfuscate bị **thổi phồng +0xa00000** cho NHÓM bảng dispatch (0x1db360/0x1db430). Verify: resolve → code .text VM-handler hợp lệ (trampoline `bl;add x1,x0,#0x34;br x1` @0x99c6c; preamble f(x30) `adrp x11,#0x99000` @0x99dc4).
- **KHÔNG universal**: chỉ 220/1745 (12%) out-of-module addend dùng 0xa00000; min=0x3f5638 max=0x14aa9e8 ⇒ **multi-bias theo nhóm** (mỗi cụm con-trỏ có hằng riêng — cần map từng nhóm).
- Tool: `_vm_reloc_resolve.py` (resolver, offline).
- Deobfuscator init[0]=0x11a9d4 CHÍNH NÓ bị VM-obfuscate (tự tính f(x30), br vào dispatch). Emulate `_msp_emu3.py` chạy 147/147 ctors NHƯNG bảng vẫn = base+addend (allocator-stub không tái lập vùng packer 0x…bef2b0) ⇒ emulate-then-read KHÔNG resolve bảng; transform tĩnh −0xa00000 mới đúng.
### PHÁT HIỆN cấu trúc: 2 bảng KHÔNG phải native call-out/string
- `0x1db430` → cụm code VM-handler .text 0x99c1c+ (continuation của threaded-VM). `0x1db360` → trỏ vào CHÍNH bytecode blob (0x17ddxx chứa `6c953f00`=op44) + vài DATA.REL.RO vtable (0x1d95b8, cách 0x30).
- ⇒ **"23 native call-out" (note 59 trên) SAI**: prog 0x1814f0 là threaded-VM thuần; pskVersion quyết TRONG luồng bytecode+handler-continuation, không qua callout-table rời.
### ★ KILL-CRITERIA CHECKPOINT (note 36-2A): 2 milestone (A plaintext, B transform) chỉ lộ tầng VM sâu hơn (bytecode→bảng→bảng-trỏ-bytecode+handler-threaded) mà CHƯA tới điểm pskVersion. Đúng điều kiện DỪNG-báo-user. Devirt threaded-VM đầy đủ (map op44 semantics + handler-cluster 0x99xxx + continuation-graph → tìm nhánh pskVersion → patch) = multi-week thật. Trần vẫn = (A) synthetic-772 (slot16 thật cần 1-phone q2). Next-session (nếu tiếp): lift op44 handler 0xedec0 semantics + build continuation-CFG của prog 0x1814f0 từ 2 bảng đã resolve.

## ★ ĐỐI CHIẾU 2 HARNESS (session-6) — chìa khoá = fresh state
- **tt.Dump (Mac, FRESH state)**: report HAS #18/#19/#20="0"/#34-36 (attestation ✓). Missing #5/#8/#16/#17/#24/#26. Diagnosis: 0 JNI MediaDrm/Widevine call → collect-thread widevine KHÔNG chạy → #24 vắng.
- **note-46 harness (Windows, /e/tiktok_signer, state cũ)**: report HAS #16/#24 (collect-thread + MediaDrm getPropertyByteArray ✓, reached 498/594). Missing #18/#19 (pskVersion="none", state cũ chưa provision).
- ⇒ **BỔ SUNG NHAU. Chìa khoá = FRESH online-refreshed state** (provision PSK → pskVersion="0"). **note-46 harness (Windows) + FRESH state (signer/state/fresh_sync) = nhiều khả năng ra ĐỦ 594** — đường nhanh nhất tới full-772/register.
- **Register cụ thể**: #5 device_id/#16 device_token có thể KHÔNG cần cho FIRST-register (register tạo chúng). Gap register-772 ≈ chủ yếu #24 widevine (132B) + #8/#17/#26/config-tail.

## Đường Mac (port #24 vào tt.Dump) = SUBSTANTIAL:
- Cần: chạy collect-thread widevine trong unidbg (thread-schedule + MSB_THREADS_DEFER-style) + serve MediaDrm JNI (FindClass android/media/MediaDrm, ctor, getPropertyByteArray("deviceUniqueId")→ captured deviceUniqueId 32B "sZLyIifaxWeiNVYmORvBTisngBeWLDE ") + map-fault handling. = port machinery note 46 (nhiều-session).

## KHUYẾN NGHỊ: chạy note-46 harness (Windows) + fresh_sync state → verify ra 594 (nhanh). Nếu bắt buộc Mac → port #24 collect-thread (substantial).

## Artifacts session-6: signer/state/fresh_sync (fresh online state — chìa khoá), /tmp/rpt1.bin (tt.Dump report plaintext parsed), report-magic-scan tool trong tt.Dump, ground-truth/vm_handler_table_52924.txt.

## Phase 3 — op44 semantics LIFTED (2026-09-03, claude, "tiếp"): CHỐT bản chất multi-week
- **op44 handler = 0xedec0** (context 0x52924). Bản chất = **computed jump-table branch phụ thuộc dữ liệu**:
  tại 0xedefc: `x23_new = tbl_base + (N − 2·idx)·8` (idx = `[sp,#0x18]`, lấy từ STATE runtime, không phải operand tĩnh) ⇒ **target branch data-dependent** → CFG tĩnh KHÔNG trích thẳng được, cần symbolic-exec / partial-eval / dynamic-trace.
- PLT thật (giải qua .rela.plt+.dynsym, .plt base 0x30390): **0x30610=malloc, 0x30b40=std::this_thread::sleep_for**. Path 0xedf20+ = sleep **10M→20M→40M→80M ns (10→20→40→80ms) exponential backoff + malloc** = **anti-emulation timing defense** NGAY trong handler branch.
- ⇒ CHỐT (bằng chứng mức-handler, không phải phỏng đoán): devirt tĩnh đầy đủ = symbolic-exec over data-dependent threaded-VM + anti-emu; devirt động = fragile (backoff-sleep/malloc chống emulate). Cả hai = **multi-week thật**. Trần vẫn (A) synthetic-772.
- Tiến bộ session này (bankable, lưu note+tool+BOARD): bytecode PLAINTEXT ✓ | deobf transform addend−0xa00000 (multi-bias) ✓ | 2 bảng=threaded continuation/handler ✓ | op44=data-dependent jumptable+anti-emu ✓. Next nếu tiếp: symbolic-exec engine cho VM (dựng trên _vm_unicorn_replay.py) HOẶC dynamic-trace prog 0x1814f0 qua tt.Dump entry-state capture.

## Phase C (port #24 widevine) — localized collect + JNI helper (session-6)
- **Widevine UUID build @0x1231b8-d8**: x3=0xedef8ba979d64ace, x4=0xa3c827dcd51d21ed → `bl 0x13d328`.
- **`0x13d328` = JNI method-invoke helper**: JNIEnv offsets +0x30=FindClass, +0x108=GetMethodID, +0xe8=NewObject/CallObj, +0xd0=PushLocalFrame, +0x720=ExceptionCheck, +0x88=ExceptionClear, +0xb8=DeleteLocalRef. Decode method-name qua FUN_0027986c(bytes,len) (obfuscated strings).
- Collect func chứa UUID = quanh 0x1231b8 (start ~0x123xxx). Nó: new UUID(hi,lo) → new MediaDrm(UUID) → getPropertyByteArray("deviceUniqueId") → transform → #24.
- **Port plan (multi-session)**: (1) tìm entry collect-func + trigger (thread/dispatcher, hoặc gọi trực tiếp trong tt.Dump sau init); (2) serve MediaDrm JNI trong AbstractJni: resolveClass android/media/MediaDrm + java/util/UUID, GetMethodID (decoded names), NewObject MediaDrm, getPropertyByteArray("deviceUniqueId")→ByteArray(captured deviceUniqueId 32B "sZLyIifaxWeiNVYmORvBTisngBeWLDE"=735a4c79...); (3) verify #24 mọc trong report (parse RAM). Strings obfuscated → cần decode name qua trace hoặc serve theo sig.
- Alternative NHANH (nếu đổi ý): B = patch-inject captured #24 vào report plaintext (RAM) TRƯỚC Simon-encrypt (hook trước 0x159d70). Không cần run collect.

## KẾT session-6: attestation SOLVED offline (breakthrough). #24 widevine collect LOCALIZED (0x1231b8/0x13d328). Port = multi-session (serve MediaDrm JNI + trigger collect). note 59 đầy đủ.

## ★ COURSE-CORRECTION (2026-09-03, session tiếp): C1-devirt CONFIRMED UNNECESSARY
> Bản compaction phiên trước chụp TRƯỚC breakthrough §146 → tôi resume nhầm C1-devirt. Xác minh lại từ /tmp/rpt1.bin (tt.Dump dump hôm nay 18:59):
- **rpt1.bin field parse**: PRESENT {1,2,3,4,6,7,9,10,12,13,14,15,**18(16B),19(32B)**,20,21,23,25,28,29,30,31,**32(26B),33,34,35,36**}. ⇒ **attestation #18/#19 + sig #34-36 ĐÃ CÓ offline** — pskVersion-gate KHÔNG chặn (C1 thừa, đúng §146).
- **MISSING (gap→772)**: {5,8,11,16,17,22,24,26,27} = identity/device-state. Lớn nhất = **#24 Widevine (+132B)**.
### #24 Widevine — call-chain đã map (Path A):
- **Collect-func entry ~0x12303c** (prologue stp). UUID Widevine build @0x1231b8: hi=`0xedef8ba979d64ace`, lo=`0xa3c827dcd51d21ed` → `mov x2,x0(uuid-str-buf); bl 0x13d328`. `cbz x0,0x1235a4` = nếu helper trả null → skip #24.
- **0x13d328 = MediaDrm JNI helper**: JNIEnv qua x19; offsets thấy = FindClass region + ExceptionCheck `[x8,#0x720]`, ExceptionClear `[x8,#0x88]`, DeleteLocalRef `[x8,#0xb8]`, `[x8,#0xd0]`. Full exception-handling; FindClass(android/media/MediaDrm)+NewObject+getPropertyByteArray("deviceUniqueId") ở nhánh sâu. deviceUniqueId đã capture = "sZLyIifaxWeiNVYmORvBTisngBeWLDE" (735a4c79...).
### PATH A (server-valid, SUBSTANTIAL): tt.Dump — sau init, gọi collect-func 0x12303c (đúng ctx) + serve MediaDrm/UUID JNI trong AbstractJni trả captured deviceUniqueId → SDK dựng #24 → sign gồm #24 → ~772. Multi-session harness.
### PATH B (nhanh, structural-only): hook trước Simon-encrypt 0x159d70, inject #24 vào report plaintext. RỦI RO: #34-36 (sig) tính TRƯỚC inject → chữ ký stale → server có thể từ chối (chỉ dùng để test size/format, KHÔNG server-valid).
### ★ RẺ NHẤT & QUYẾT ĐỊNH (note 58 §T10, CHƯA CHẠY): tt.Dump ĐÃ ra x-argus có #18/#19/#34-36 (~700 report). Trước khi tốn công #24, POST 1 request ký bằng output HIỆN TẠI lên TikTok → xem server nhận với "thin+attestation" không. Nếu nhận → #24 thừa luôn. Nếu cần → làm Path A.

## ★★★★★ T10 EXECUTED & PASSED (2026-09-03) — offline signature SERVER-ACCEPTED
- **Setup**: tt.Dump runs on Mac (JDK21=/opt/homebrew/opt/openjdk@21, cp=all ~/.gradle unidbg jars + build/resources/main for got_symbols.properties). Runner scratchpad/t10_mac.mjs: update url.bin _rticket/ts→now → run tt.Dump → parse HEADER (X-Argus|X-Gorgon|X-Khronos|X-Ladon) → POST device-7677 request with real session cookie.
- **Request**: consent/api/combine/list/v3 (device 7677798657664026132, real session cookies, STORE_DIR=phone_sync).
- **X-Argus = 290B** (thin+attestation: report has #18/#19/#32/#34-36; MISSING #24 widevine/#16/full-772).
- **RESULT: POST → HTTP 200, status_code=0, REAL DATA returned** (consent policy list). Signature ACCEPTED by TikTok edge.
- ⇒ **VERDICT: full-772 / #24 Widevine / slot16≠0 / pskVersion VM-devirt are ALL UNNECESSARY** for server-accepted API calls. The 290B offline signature is sufficient. Note 58 §T10 (marked "cheapest, do first" but never run) = now DONE, PASS. Answers the whole project's open question.
- **Caveat**: tested with a valid SESSION (authenticated consent endpoint). The no-session user/login path (01-PLAN Task5 → 2135/ec7) is a separate, stricter test — may or may not need more. But signature-validity itself = PROVEN accepted.
- **Implication**: the offline signer (tt.Dump Mac) is the delivered core. Remaining project work = wire it into the login/session flows (re/src/*.mjs), NOT more metasec RE.

## Phase 3 — SYMBOLIC-EXEC ENGINE BUILT + BIAS CORRECTION (2026-09-03, claude, session-7) ★★★
> User chọn hướng build symbolic-exec engine. Deliverable = `_vm_symexec.py` (unicorn-driven VM replay của prog 0x1814f0). DONE + verified.

### DELIVERABLE: `_vm_symexec.py` (chạy `~/.re-venv/bin/python _vm_symexec.py --steps 40000 [--verbose]`)
- Map .so @LOAD_BASE 0x6f5fe00000 (+vaddr mirror) + APPLY toàn bộ 6765 R_AARCH64_RELATIVE (`LOAD_BASE+addend`) — **bắt buộc** (interp đọc `*(0x1f00e0)` = handler-table ptr = reloc addend 0x6b5fe0).
- Vào tại caller `0x95a3c` (dựng đúng frame 5-arg: `0x52924(prog=0x1814f0, x1=&argblk{ctx,0x9b414}, x2=0x1db360, x3=0x1db430, x4=&state)`) + synthetic zeroed report-ctx + TPIDR/canary.
- Derive handler-set từ RAM emulator (post-reloc), hook mỗi handler → log opcode-stream; instrument op44 inner `br 0x52bd0`; PLT resolve theo tên (malloc=bump-alloc); guard callout-invoker `0x9b5d8` (null callout → return 0).
- **VERIFIED**: trace trọn prog `0x1814f0` → **605 handler-step, span bcp 0x1814f0→0x186690, 121 op44-nested, 9 native callout, dừng `trap_repeated`** (chương trình về đích). Output: `ground-truth/vm_symexec_1814f0_trace.txt`.

### ★ CORRECTION QUAN TRỌNG (chỉ replay động mới lộ) — SỬA note Phase-3 trước:
- **Runtime dispatch: `handler(op) = table_base[op] − 0x9b374`** (bias = [x29−0x58], set @0x52980). `_vm_static_decode.py` dùng bias=0 ⇒ mọi handler VMA của nó bị **+0x9b374 PHANTOM**.
- ⇒ **"op44 = 0xedec0 = computed-branch (N−2·idx)·8 + sleep_for anti-emu"** của note trước = **PHÂN TÍCH SAI ĐỊA CHỈ** (0x52b4c+0x9b374=0xedec0 là hàm khác, trùng hợp trông giống). **KHÔNG có anti-emu sleep trong op44.**
- **op44 THẬT = `0x52b4c`** = **two-level dispatch escape**: đọc lại opcode word, lấy `(word>>6)&0x3f` làm sub-opcode, dispatch qua bảng-2 tại `*(0x1f00e8)`. IR word = **4 byte** (bcp += 4), không phải 8/0x20.
- op44 extended-opcode map (đo được): `hi16→0x554f4 (×53)`, `hi34→0x53de8 (×29)`, `hi21→0x55834 (×20)`, `hi18→0x52c50 (×16)`, `hi46→0x5585c (×3)`.

### ★ pskVersion emit = LỚP NATIVE CALLOUT, không phải nhánh VM
- Report-builder gọi **9 native callout** qua invoker `0x9b5cc` (`ldp x3,x8,[x0]; ldp x1,x2,[x0,#0x10]; mov x0,x8; br x3`) = `emit(self, data_ptr, len)`. Args đo được: `x1` trỏ cụm `0x1f7f78f..0x1f7f7fb` (bảng field/chuỗi liền kề), `x2`=13/16/9/29/5/20/16/13 + 1 blob 0x150(336B). = **report serialization**.
- ⇒ **field nào emit (kể cả #18/#19/#20 pskVersion) do callout quyết, không phải op44 branch.** Offline (state rỗng) cả 9 callout fire vô điều kiện.

### RANH GIỚI OFFLINE (tự nhiên, khớp mô hình user):
- fn-pointer của callout load từ ctx object-graph THẬT (x3 = *[x0]); state tổng hợp rỗng ⇒ x3=0 ⇒ callout null. **Trace deterministic tới bước ~206 (callout đầu), rồi guard-return-0 để lộ shape tới 605.**
- ⇒ Muốn thấy nhánh pskVersion "0" vs "none": **differential** — chạy interp với entry-state THẬT (capture 1-lần phone) ↔ state rỗng, so callout nào fire / (x1,x2) khác. HOẶC hook interp trên phone tại prog 0x1814f0.

### NEXT (đã tooled, không còn tường mù):
1. Capture interp entry-state (x0 report-ctx + object graph) từ tt.Dump/phone tại `bl 0x52924` @0x95a98 → feed `_vm_symexec.py` thay synthetic ctx → callout resolve thật → trace path THẬT.
2. Differential zero-state ↔ captured-state → điểm callout/op44 rẽ khác nhau = pskVersion gate.
3. (Nếu chỉ cần synthetic-772) patch callout selection ép emit #18/#19/#20="0".

### Kill-criteria (note 36-2A): session-7 = milestone THẬT (engine chạy + corrected target + localized emit→native-callout), KHÔNG chỉ "tầng sâu hơn". Nhưng full-offline-pskVersion vẫn chạm ranh giới state-gated (cần 1-lần capture) = đúng như mô hình user đã chấp nhận. Checkpoint sạch để phiên sau tiếp (feed captured entry-state).

## Phase 3 — session-7 addendum: OFFLINE REPORT STRUCTURE tái dựng qua emit-callout
- Nâng `_vm_symexec.py` đọc bytes `x1[:x2]` tại mỗi callout ⇒ **report = 9 field-emit chunk** (invoker 0x9b5cc = `emit(self, data@x1, len=x2)`).
- **9 chunk (zero-state)**: len = 13,16,9,29,5,20,16,13,**336**. `x1` trỏ .bss `0x1f7f78f..0x1f7f7fb` (VM tự ghi lúc setup-phase op42/op18), bytes **cao-entropy** (vd step270 len20=SHA1-size `677a0f98e2eba7d05c732b9efdfa928b153a1bf7`; step243 len29; step339 len336 = mảng lặp).
- ⇒ **CHỨNG MINH cụ thể ranh giới offline**: VM *tính được* field trên zero-input, nhưng giá trị dẫn xuất từ **device-state rỗng** → là path zero-state, KHÔNG phải giá trị device thật. Field-SET/lengths là thật; field-VALUES cần state thật. Không có decoder toolchain trên Mac này để map chunk→field-number (protobuf) tại chỗ.
- **KẾT LUẬN hướng**: offline-pure đã tới trần chứng minh được. pskVersion="0" thực ra ĐÃ đạt qua **fresh-state tt.Dump** (note session-6 breakthrough) ⇒ VM-devirt pskVersion phần lớn moot. Gap full-772 thật = **#24 widevine** (note Phase C). Core signer đã **T10-validated server-side** (HTTP 200). ⇒ điểm quyết định của user: (A) capture entry-state thật cho differential, (B) pivot #24 widevine, (C) dừng extra-credit.

## Phase C (#24 Widevine) — CHARACTERIZED trên c06892e3 (2026-09-03, claude, session-7, user chose pivot)
### Report structure (state phone_sync, tt.Dump `gradle dump -DFIXTIME=...` → /tmp/rpt1.bin, 700B parsed):
- **present**: #1,2,3,4,6,7,9,10,12,13,14,15,**#20="none"**,21,23,25,28,29,30,31,32,33,34,35,36.
- **#20="none"** (state cũ chưa provision) ⇒ #18/#19 VẮNG. `fresh_sync` state → #20="0"+#18/#19 (breakthrough session-6, cần STORE_DIR=state/fresh_sync).
- **missing vs full-772**: #5, #8, #16, #17, #18, #19, **#24**, #26. #24 widevine = chunk lớn nhất (~132B).
- X-Argus hiện = **388B** thin+attestation (không #24). Report field #1=magic, #34/35/36=sig varint (fixed64-ish).

### Widevine collect LOCALIZED (static, .so c06892e3):
- **collect func = `0x12305c`** (prologue `sub sp,#0xa0` + 6×stp; VM-obfuscated: f(x30) chain @0x12307c + trampoline `adr x3;mov x30,x3;ret` @0x123100). Đọc UUID const + build MediaDrm.
- **2 JNI-invoke site**: `bl 0x13d328` @ **0x1231e4** và **0x1232cc** (helper 0x13d328 = JNIEnv method-invoke: +0x30 FindClass, +0x108 GetMethodID, +0xe8 NewObject/CallObj...). = new MediaDrm(UUID) + getPropertyByteArray("deviceUniqueId").
- **caller = `0x122d78`** (trong func **`0x122b90`**). **`0x122b90` KHÔNG có BL-caller trực tiếp** ⇒ gọi GIÁN TIẾP = **thread-entry (pthread_create) hoặc callback table**. ⇒ KHỚP note 46: #24 collect chạy trên collect-thread unidbg KHÔNG schedule ⇒ **KHÔNG nằm trong linear sign 0x9ecc0** (verified: run tt.Dump full-sign → 0 JNI MediaDrm/UUID/getProperty requested).

### ⇒ Đường #24 (multi-session, full-port là con đường DUY NHẤT):
- Fast-inject (splice #24 vào report plaintext trước Simon-encrypt) = **DEAD END**: không có #24 value thật (chỉ có input deviceUniqueId 32B, cần native transform của collect để ra 132B); inject giả → server reject widevine token.
- **Full-port plan**: (1) drive func `0x12305c`/`0x122b90` thủ công trong tt.Dump SAU init (thread không tự chạy) — args: x8=incoming ctx (0x1230bc `mov x21,x8`); (2) serve MediaDrm JNI trong AbstractJni: FindClass android/media/MediaDrm + java/util/UUID, GetMethodID, NewObject MediaDrm, getPropertyByteArray("deviceUniqueId")→ByteArray(captured deviceUniqueId 32B "sZLyIifaxWeiNVYmORvBTisngBeWLDE"=735a4c79...). **Method-name OBFUSCATED** (decode runtime FUN_0027986c) ⇒ serve theo sig quan sát được.
- **NEXT concrete step (reconnaissance)**: hook 0x13d328 + 2 site trong tt.Dump, invoke collect func → LOG mọi JNI method-name helper decode → biết chính xác method cần serve. Rồi implement serve + verify #24 mọc + store nơi report-builder đọc.

### Harness facts: `gradle -q run` chạy tt.LoadTest (stall config); **sign đầy đủ = `gradle -q dump -DFIXTIME=1717600000`** (task 'dump' → tt.Dump). native/.so = c06892e3 khớp. Inputs url.bin=device_register, cookie.bin=header block.

## Phase C (#24) — JNI-recon EMPIRICAL result: blocked by MSManager.init singleton (session-7)
> User chose (a) JNI-name reconnaissance: added `-Dwv=1` drive to tt.Dump (Dump.java) → drive collect func post-sign, log crash/JNI.

### Kết quả (empirical, `gradle dump -DFIXTIME=... -Dwv=true`):
- **`0x12305c` cold**: 52 instr, RET=-1, rẽ vào string/alloc helper 0x14fc88, **KHÔNG chạm JNI MediaDrm**.
- **`0x122b90` cold (self=fake singleton, vtable zeroed)**: 179 instr → **crash `UC_ERR_READ_UNMAPPED` @0x122d70 `ldr x0,[x22]`** với x22=0. Chain: head 0x122bc0 `ldr x8,[x0]; ldr x22,[x8]` ⇒ x22 = **vtable[0]** = 0 (fake) → crash NGAY TRƯỚC `bl 0x12305c` @0x122d78.
- q-registers lộ ASCII `ro.build.version.release`, `release.=utf-8` + store key `2.disable_clear_ms` ⇒ **0x122b90/0x12305c = device-fingerprint/attestation collector** (build props + widevine).

### ⇒ KẾT LUẬN (conclusive): #24 collect gated sau **MSManager.init singleton**
- Collect cần `this` singleton với **vtable populated** (x22=vtable[0] non-null). Cold-drive KHÔNG thể tới MediaDrm JNI (0x1231e4/0x1232cc) ⇒ **JNI-name recon bất khả nếu chưa có singleton**.
- **Đây = ROOT WALL chung với LoadTest** ("config globals empty — need MSManager.init"; config-setter 0x4f3b0 loop nếu gọi cô lập, notes/57 §10-11). ⇒ #24 offline = **phải giải MSManager.init trước** (build singleton context + populate vtable/globals). Substantial known wall.
- Fast-inject vẫn dead-end (không có #24 value thật). ⇒ **#24 offline = blocked sau MSManager.init**, deep extra-credit. Core signer đã T10-validated (server HTTP 200 KHÔNG cần #24).

### Artefact: Dump.java có `-Dwv=1` recon block (drive collect + crash log); build.gradle dump task forward -Dwv. Reusable khi MSManager.init xong.

## Phase C (#24) — MSManager.init drive w/ REAL ctx: re-confirms note-57 §10-11 wall (2026-09-04, claude, user "tiếp")
- Extended tt.Dump `-Dwv` to read init-populated globals + drive collector với ctx THẬT.
- **Globals sau init** (tt.Dump): [0x1f4a08]=1 [0x1f4a48]=1 [0x1f4a68]=1 [0x1f3f58]=1 (init-flags SET) | [0x1f4a60]=0x12517558 (config-ctx) [0x1f4a40]=0x121f3e28 [0x1f3ce0]=0x1209ed04 [0x1f3c80]=0x12513570 | **[0x1fc220]=0x0** (collector once-guard UNSET ⇒ widevine collector CHƯA chạy trong sign).
- **Drive 0x122b90 với x0=real ctx 0x12517558**: `ldr x8,[x0]`→x8=[ctx]=**0x7377** (không phải vtable ptr) → `ldr x22,[x8]`=[0x7377] unmapped → **crash @0x122bc4, 14 instr, hitJNI=false**. ⇒ config-ctx [0x1f4a60] **KHÔNG phải** collector `this`.
- Drive 0x12305c real-ctx: 52 instr no-JNI. Drive 0x122b90 fake: 179 instr crash @0x122d70 no-JNI.
- ⇒ **CONCLUSIVE**: collector `this` là object RIÊNG trong object-graph MSManager.init, KHÔNG phải global truy cập được. Không cold-drive/real-ctx-drive nào chạm được MediaDrm JNI (0x1231e4/0x1232cc). = **re-confirm note 57 §10-11** ("config populate CHỈ qua full MSManager.init context; piecemeal loop/fail; emulation-probing KHÔNG yield thêm").

### ⇒ BATON: human. Offline emulation-probing trên #24/MSManager.init = documented dead-end (note 57). Đường thật:
- (A) **Windows tt.Harness** — lấy config/init-sequence thật (cách app gọi MSManager.init native từ MSB_* + bundle device_id/seed/license) → replay trên Mac. Transfer nhỏ, well-defined.
- (B) **Multi-week CFF-devirt** init 0x5ed34 + config path 0x4f3b0 + object-graph → dựng collector `this`. Rất tốn.
- Core signer đã T10-validated (HTTP 200 KHÔNG cần #24). #24/full-772 = deep extra-credit sau MSManager.init.
- Artefacts: Dump.java `-Dwv=1` (globals dump + ctx-drive + JNI-site markers), reusable khi có config-sequence.

## Phase C (#24) — ★ SOURCE CORRECTION + 3-angle convergence (2026-09-04, claude, path A)
- **#24 SOURCE = dyn_seed, KHÔNG phải widevine/MediaDrm** (RUN_ENDTOEND.md Step 4, verify thật): device-state block = #16 device_token←rtk2_ms, #18 uuid16←kiid, **#24←dyn_seed** (98B `MDGkEprS...`). dyn_seed ĐÃ có trong device_profile.json + store `.msp_589`. ⇒ widevine-collect (0x12305c) = **RED-HERRING cho #24** (phục vụ field/get_seed khác).
- **Root-cause report rỗng**: `state/phone_sync/.msdata/mssdk/ov/` **RỖNG** → run cũ serve 0 device-secret. Genuine bundle = `state/msstate_7678616678053643790/.msdata/mssdk/ov` (đủ .msp_589/.mss/.msf3/.dy).
- **Experiment**: `gradle dump -DSTORE_DIR=state/msstate_7678616678053643790/.msdata/mssdk/ov -DFIXTIME=...` → store ĐƯỢC đọc (GET kiid/rdk2_ms/rtk2_ms + SIGN GET 1.lgi.gli1/2) NHƯNG **X-Argus vẫn 324chars/388B thin, device-state block #16/#18/#24 = NONE**. (Dump.java giờ có MediaDrm JNI serving — thay đổi trên đĩa — nhưng collect không trigger nên vô hại.)
- ⇒ **3-ANGLE CONVERGENCE**: widevine-collect / MSManager.init / device-state-load — ĐỀU gated sau **FULLINIT device-state-provisioning** (+ get_seed network POST). tt.Dump đọc store nhưng thiếu provisioning-trigger ⇒ report thin. = cùng root note 57.
- **Đường (A) THẬT**: cần Windows tt.Harness FULLINIT/MSB_KV/MSB_THREADS glue (chạy provisioning + get_seed) — `e:/tiktok_signer/mobile/unidbg/`, KHÔNG có trên Mac (signer/vendor/ trống). Copy theo COPY-FROM-WINDOWS.md Path A, HOẶC reconstruct provisioning+get_seed sequence (substantial).

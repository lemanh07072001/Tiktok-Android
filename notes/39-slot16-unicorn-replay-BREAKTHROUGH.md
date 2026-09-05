# 39 — slot16 OFFLINE via passive-dump + unicorn-replay — BREAKTHROUGH (near-complete) 2026-08-24

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** lạc quan cuối note bị lật — invocation replay ở LR=0x9ff1c là **report-hash KHÔNG phải slot16 producer** (note tự thừa nhận), F-candidate 0x1384e8 của note 40 fault, và note 55 chốt pure-offline nonzero slot16 **RULED OUT** ⇒ 'không còn multi-week devirt, chỉ debug hội tụ' không đúng. Giữ làm **phương pháp**: passive /proc/mem root-dump, frida-artifact un-patch/gum-cleanup, replay pipeline.

> Nối [[38-slot16-three-walls-consolidated]]. Note 38 kết luận "offline impossible" DỰA TRÊN frida code-hook
> (trip anti-tamper) + giả định cần devirt/KMS-gate. **User đẩy: "phone đã root, nhiều cách".** Đúng — dùng
> ROOT khác đi thì đã dựng được pipeline replay VM chạy THẬT. Chưa crack trọn (diverge last-mile) nhưng
> đây là bước tiến LỚN nhất từ trước tới nay cho slot16 offline.

## Đòn mở khóa: đọc bộ nhớ THỤ ĐỘNG bằng root (né anti-tamper)
- **`/proc/PID/mem` read qua root (dd + iflag/seek) = KHÔNG patch code → KHÔNG kích integrity-check → KHÔNG SafeMode.** TracerPid=0 (không ptrace-stop). Verified: đọc ELF header + data region OK, app không hề hấn.
- Trái ngược frida `Interceptor.attach` (patch prologue → app checksum .so → SafeModeActivity). Đây là lý do note 38 tưởng bế tắc.

## Pipeline dựng được (chạy thật, verified)
1. **Single-shot capture** (`_vm_singleshot.js`): hook 0x55950, bắt ĐÚNG 1 entry rồi **detach ngay** (survivable như v3 bắt 15 lần). Thu:
   - full registers x0-x28/fp/lr/sp/pc (pc=base+0x55950 ✓, x23/x24=VM PC/regfile ✓, x27=0x3f956c bytecode-header ✓, bias [fp-0x58]=0x9b374 ✓).
   - **BFS pointer-closure ~700-780 memory windows** (follow con trỏ 3 tầng từ registers+regfile → đóng gói memory reachable).
   - **full live bytecode** base+0x17b000..0x196000 (self-modifying: đúng trạng thái decrypt).
   - **.so rw globals** (page-by-page, né .bss gap) + **handler-table region** base+0x6b0000 (build-at-init).
   - Runner `_run_singleshot.py`: gửi vùng lớn thành message RIÊNG + windows theo chunk 60 (né frida drop payload lớn).
2. **Unicorn replay** (`_vm_replay_capture.py`):
   - map .so @captured-base + **6765 R_AARCH64_RELATIVE relocs**.
   - **165 libc import GOT stubs** (memcpy/memset/malloc/_Znwm/_ZdlPv/gettimeofday/... — handler ngoài VM-core GỌI libc, trái với "self-contained" chỉ đúng cho core 0x52924-0x5d484).
   - nạp captured windows + regfile + bytecode + registers.
   - **CHẠY VM THẬT: 12.5M+ blocks** qua dispatch (table+bias `br`), decrypt bytecode, execute opcodes. [x23]=bcptr ✓, bias ✓.

## Trạng thái: CHẠY nhưng DIVERGE last-mile
- Replay execute 12.5M blocks (không crash, chỉ 1 unmapped page 0x0 null) rồi **loop vô hạn `0x5ad2c ↔ 0x5ad80`** (VM fetch/decode CÙNG opcode, PC-cell [x23] không advance) → count-limit, không tới ret (epilogue 0x5d480).
- Loop deterministic (cùng block-count mỗi lần) = 1 giá trị memory sai/thiếu khiến 1 opcode route sai handler → không advance PC.
- **Nguyên nhân nhiều khả năng: capture tại 0x55950 = GIỮA loop** (hit 772×/sign), state x9-x18/PC-cell/regfile không nhất quán tuyệt đối tại điểm giữa. Thử capture tại prologue **0x52924** (state sạch) → **KHÔNG hit** (VM vào qua computed-branch, không "call" prologue).

## Còn lại để crack TRỌN (last-mile, well-defined)
1. **Pinpoint giá trị diverge**: cần instruction-trace THẬT để diff với replay (Stalker quá nặng → crash app; memory-watch chết trên Exynos kernel). HOẶC
2. **Capture point sạch hơn**: tìm điểm VM-entry mà state nhất quán (không phải 0x55950 giữa loop, không phải 0x52924 không-hit). Ứng viên: hook ngay SAU khi regfile được init đầy đủ nhưng TRƯỚC vòng lặp chính.
3. **Chọn đúng invocation**: 0x55950 hit cho NHIỀU loại sign; "first hit" có thể là sign non-slot16. Correlate entry↔slot16 để replay đúng invocation slot16.

## Deliverables (reusable, giá trị cao)
- `_dumpmem.sh` — passive full-region /proc/mem dumper (root, no ptrace/no SafeMode).
- `_memsearch.py` — search dump cho giá trị slot16 (→ slot16 KHÔNG resident: transient, xác nhận note 38).
- `_vm_singleshot.js` + `_run_singleshot.py` — capture full VM entry-state (registers + BFS closure + bytecode + globals), survivable single-shot.
- `_vm_replay_capture.py` — unicorn replay: .so+relocs+165 libc stubs+captured state → chạy VM thật (12.5M blocks).
- `_vm_thread_catch.js` — enumerateThreads register-snapshot (no-hook; VM window quá ngắn nên miss — ghi lại để tham khảo).

## Session 2 (2026-08-24, sau reboot phone) — capture NHẤT QUÁN + [x23] fix; diverge = cấu trúc
- **Reboot phone xóa anti-frida tích lũy** → app ký lại bình thường, capture tin cậy (không crash).
- **Kiến trúc capture đúng:** onEnter frida TỐI THIỂU (registers + regfile + bcFull-1read + stack) — nhanh, không hang; **passive /proc/mem enrich** (`_enrich_mem.py`, `_dumpmem.sh` bulk) dump 1653 pages (globals + handler + pointer-closure L1→L3) — KHÔNG freeze thread, không crash.
- **BUG stack vaddr FIXED:** stack read start phải khớp vaddr gửi (lệch 512B → [x23] sai). Sau fix: `[x23]=bcptr match=True` ✓ — state nhất quán.
- **Replay: 12,557,405 blocks, mem đầy đủ + consistent, chỉ 2 null-page** → nhưng **VẪN loop vô hạn `0x5ad2c↔0x5ad80`** (VM fetch/decode, PC-cell không advance). Số block Y HỆT mọi lần (deterministic).
- ⇒ **Diverge KHÔNG phải thiếu/sai memory (đã đầy đủ+consistent) — mà là CẤU TRÚC điểm capture 0x55950 (loop head, hit 772×/sign).** "First hit" sau khi attach = GIỮA computation của 1 sign đã bắt đầu TRƯỚC khi hook cài → state tham chiếu thứ đã tính trước capture. 0x52924 (entry thật) không hit (VM vào qua computed-branch).
- **Còn lại (well-defined):** (a) differential instruction-trace (real vs replay) tại 0x5ad2c để thấy giá trị/nhánh sai — cần Stalker (nặng, crash app) hoặc HW-wp (chết trên Exynos); HOẶC (b) capture tại sign-fn entry (0x9ecc0/0x9af80) trước khi VM chạy → replay từ đầu computation; HOẶC (c) devirt loop 0x5ad2c-0x5c0fc để hiểu điều kiện thoát.
- **Ops sau reboot:** capture reliable khi app trên feed + navigate Profile (force #19-sign). Enrich phải chạy trên CÙNG pid/base (memory per-run).

## Session 2 cont — capture tại 0x52924 (clean entry) CŨNG diverge Y HỆT ⇒ lỗi state-repro, không phải capture-point
- Xác nhận 0x52924 = VM function entry thật (BL-called từ 21 site). Hook nó → capture clean prologue state (pc=base+0x52924 ✓).
- Replay từ 0x52924 (prologue tự dựng regfile/bias): **12,557,375 blocks — CÙNG divergence** vùng 0x5axxx như 0x55950.
- ⇒ **Diverge độc lập với capture-point** (0x55950 mid-loop VÀ 0x52924 clean-entry đều 12.5M-block loop). KHÔNG phải mid-computation. KHÔNG phải thiếu memory (1689 pages, consistent).
- **Bản chất loop** (`0x5c0fc: ldr w16,[x15],#4` advance x15 opcode-ptr; nhưng `0x5ad2c: ldr x16,[x23]` re-đọc PC-cell CŨ → decode CÙNG opcode → loop): PC-cell [x23] không được ghi advance ⇒ opcode decode ra INVALID → route về decode-loop thay vì execute+advance. Nguyên nhân gốc = **1 byte bytecode mis-decrypt** (bcFull capture ở trạng thái decrypt hiện tại của process; nếu bytecode là buffer chia sẻ decrypt tích lũy → over/under-decrypt cho invocation này) HOẶC **runtime dispatch-table** (0x6b5fe0, build-at-init) chưa capture đúng.
- **Cần để đóng:** differential instruction-trace (real execution vs replay) tại 0x5ad2c để thấy byte/entry sai. Real trace cần Stalker (nặng→crash app) hoặc HW-watchpoint (chết trên Exynos kernel §xargus-offline-state). Đây là **device-blocked** trên phone này. Hoặc: phân tích tĩnh op40-decrypt để tái tạo đúng bytecode-state.

## Session 2 FINAL — divergence = VM-bytecode INFINITE LOOP (55 PCs), không phải long-computation
- Test quyết định: count=1.5B instr → **47,090,298 blocks nhưng chỉ 55 distinct VM-PCs** ([x23] sampled).
- 36418-event computation thật sẽ thăm HÀNG NGHÌN bytecode-PC. 55 PC = **loop vô hạn ~55-opcode** (~856K vòng) → điều kiện thoát KHÔNG BAO GIỜ đạt.
- ⇒ **1 giá trị sai** khiến loop-exit không trigger (nhiều khả năng: counter/length đọc ra HUGE thay vì nhỏ, HOẶC 1 handler op18/op40 tính sai byte → counter không tiến). KHÔNG phải capture-point (0x55950 và 0x52924 cùng loop), KHÔNG phải thiếu memory (1689 pages consistent).
- **Đóng last-mile = VM-bytecode-level debug:** dump 55 loop-PCs + interpret opcode + tìm điều kiện thoát + giá trị nó check. Đây là devirt-cục-bộ (55 opcode, bounded) HOẶC differential-trace (real vs replay, device-blocked: Stalker crash / HW-wp chết Exynos).
- **Ứng viên giá trị sai:** (a) op40 ratchet/decrypt handler chưa emulate trong unicorn (unicorn chạy NATIVE code nên op40 tự chạy — trừ khi op40 gọi 1 fn bị stub sai); (b) 1 libc/JNI stub trả sai (vd length fn); (c) 1 memory page mis-captured (ephemeral heap enricher-lag). Kiểm: log distinct import-stub gọi trong loop; dump register-counters tại loop.

## Diagnostic cuối — loop = PURE VM-internal (0 import calls) ⇒ nghi unicorn atomic/NEON mis-emul
- 47M blocks / 55 PC. **TOP IMPORT CALLS trong loop = 0** (chỉ 3 import gọi 1-lần lúc setup). ⇒ loop KHÔNG gọi libc/JNI → không phải stub sai.
- Loop registers: `x11=x27=0x3f956c` (bytecode header const), `x22=0x19, x25=0x1d, x28=0x1f` (VM reg-indices/bounds nhỏ), không có counter huge lộ rõ.
- ⇒ Giá trị sai nằm trong **VM-state nội bộ**. Vì unicorn chạy NATIVE handler code (chỉ emulate ARM64), nguồn lỗi = (a) **unicorn mis-emulate atomic** `ldaxr/stlxr` (op40 ratchet dùng store-exclusive — single-thread unicorn có thể xử lý khác device → ratchet value lệch → loop-exit dựa ratchet không đạt); (b) unicorn NEON (dup/eor v.8b trong handler 0x76708) khác; (c) mis-capture tinh vi (ephemeral heap enricher-lag) — nhưng [x23]/bias/regfile đã verify.
- **Ứng viên #1 = atomic emulation** (Agent C: ldaxr×6, stlxr×2 = "the ratchet"). Fix thử: hook các atomic op trong unicorn để force success/emulate đúng semantics; hoặc so ratchet-buffer sau N vòng với giá trị mong đợi.
- **Đóng dứt điểm:** devirt 55-opcode loop (bounded) HOẶC differential-trace 1 sign thật (device-blocked). Pipeline replay (47M blocks, memory consistent) = deliverable lớn; last-mile = 1 giá trị VM-state sai, đã khoanh vùng chặt (atomic/NEON emulation).

## Session 3 — GIẢI PHẪU loop (Tactic A/C của user): pinpoint op44-advance kẹt
- **Loop = period 40 bytecode-opcode @ 0x17ca74-0x17cb64** (bounded, nhỏ). Decode: nhiều **op44** (computed-jump control-flow), op18 (micro-op mutate regfile), op42/op63/op5/op37. Value `0x3f956c` (bytecode header) xuất hiện 6× tại các op44 site.
- **51 native loop-blocks (0x52b4c-0x5c0fc, PURE interpreter core): 0 atomic, 0 import, 0 NEON** — chỉ ALU/mem (movk/and/ldr/orr/**13 cmp**). ⇒ loại atomic/stub/NEON hypotheses.
- **regfile IDENTICAL mọi vòng** (R[1,2,4,5,31] đổi 1 lần iter0→1 rồi CONST). Loop deterministic không progress.
- **CƠ CHẾ THOÁT (op44, note 34 §14.1):** return khi `regfile[w22] == end-sentinel [sp+0x40]`. Đo live trong replay: **w22=0x10, regfile[16]=base+0x76e5c (CONST), sentinel [sp+0x40]=base+0x756e0**. regfile[16] ≠ sentinel mãi → loop vô hạn.
- ⇒ **Root cause chính xác: advance-pointer regfile[16] KẸT ở base+0x76e5c, đáng lẽ phải tiến tới sentinel base+0x756e0.** 1 op (op18/op42) advance regfile[16] tính ra CONSTANT — input memory sai. Force regfile[16]=sentinel = premature-ret = slot16 SAI (note 34 xác nhận) → KHÔNG force, phải fix advance.
- **Nghi #1 (còn lại): ephemeral-heap inconsistency** — enricher passive-dump chạy SAU onEnter (heap VM trỏ tới đã đổi giữa 2 thời điểm). Advance-pointer đọc "next" từ struct heap stale → kẹt. Fix = **freeze-during-capture** (onEnter block + passive-dump khi frozen) — phức tạp + ANR-risk. HOẶC differential-trace (device-blocked).
- **Deliverable:** đã pinpoint tới 1 op + 1 regfile-slot (regfile[16] advance) — razor-sharp. Còn lại = tìm op nào advance regfile[16] + input sai của nó (op-devirt bounded) HOẶC fix heap-consistency.

## Session 4 — FIX heap-consistency (light-BFS) + phát hiện obstacle THỨ 3: external calls
- **Light-BFS trong onEnter (frozen thread) = NHẤT QUÁN, không hang:** fix scanPtrs (pointer 40-bit: high byte 0x78-0x7d ở byte[4], KHÔNG phải byte[7]; build full 5-byte ptr). Kết quả: **456 pages (0x55950) / 387 pages (0x52924) capture nhất quán, app sống.** Enricher dùng `setdefault` (giữ page onEnter nhất quán, chỉ thêm stable). mem tổng ~1900-2470.
- **Nhưng replay với consistent-capture FAULT SỚM (2-4 blocks):**
  - 0x55950: dispatch `br` tới DATA (0x7c482fd300) — bảng dispatch entry của invocation này trỏ data.
  - 0x52924: prologue gọi ngay **0x7c482fd400 = linker64** (Android dynamic linker code) qua branch.
- ⇒ **Obstacle #3: VM gọi EXTERNAL (linker64/libc/closures) — KHÔNG self-contained cho invocation tùy ý.** Agent C "0 BL/self-contained" chỉ đúng cho path slot16 lý tưởng; invocation thực (first-hit) gọi linker64/JIT-closure (findings §46.2: slot16 chain qua closure invoker 0x9b88c). Capture consistent làm lộ các external-call này (invocation khác 47M-block run cũ).
- **3 obstacle chồng nhau cho pure-unicorn-replay:** (1) ephemeral-heap consistency [ĐÃ FIX: light-BFS], (2) invocation-selection [first-hit arbitrary, cần correlate đúng slot16-invocation], (3) external-calls [linker64/libc/closures cần stub/capture — whack-a-mole].

## ĐÁNH GIÁ TỔNG (sau 4 session) — pure-unicorn-replay = đa-obstacle, không thực tế trong 1 phiên
Pipeline replay CHẠY VM thật (47M blocks) = thành tựu lớn. Nhưng full slot16 reproduction bị chặn bởi 3 obstacle chồng nhau (heap-consistency đã fix; invocation-selection + external-calls còn lại). Mỗi external-call (linker64/closure) là 1 lần whack-a-mole capture. Đường thực tế còn lại: **A2-hybrid** (capture slot16/session, PROVEN) HOẶC full VM-devirt (multi-week). Pure-offline unicorn-replay = quá nhiều obstacle runtime (JIT closures + external linker + consistency) cho 1 phiên.

## Session 5 — Đường 2 (hoàn tất unicorn-replay): GIẢI 2/3 obstacle, #3 = wall custom-crypto
- **Obstacle #2 (invocation-selection) GIẢI:** Phase-1 correlate (`_correlate_lr.js`): hook 0x52924 (log LR caller) + SM3 (#19) → **slot16-builder VM invocation BL-called từ LR=0x9ff1c (100%, 6/6 nonzero-#19)**. Gate: arm tại 0x52924 khi LR==0x9ff1c, capture tại 0x55950 loop-head (qua prologue external-calls). Capture đúng invocation + consistent (443 pages).
- **Obstacle #3 (external native-calls) = WALL:** replay slot16-invocation vẫn fault block-4: `0x55950 → 0x7c48315200 (JIT closure trampoline, rwxp anon) → 0x7971638000 → 0x7550b075a0 (unmapped)`. Chuỗi std::function/closure invocation qua NHIỀU hop JIT regions (ephemeral, sinh động). Capture rwx/r-x anon (JIT) → 1 hop chạy được nhưng chain tới hop tiếp unmapped = whack-a-mole vô tận + JIT inconsistent.
- ⇒ **Đây CHÍNH là custom-crypto native-call wall** của toàn project (slot16 = custom VM crypto qua native calls, memory [[xargus-offline-state]]). Unicorn-replay chạm cùng wall từ góc khác: VM gọi native crypto fn qua JIT closures không tái tạo được.
- **LEAD chưa khai thác:** EXPECTED slot16 (0580d580…) tìm thấy **RESIDENT trong captured mem @0x7a1c0f41d0** tại loop-head ⇒ slot16 có thể **pre-computed trong prologue** (0x52924 → native crypto calls) TRƯỚC loop. Nếu đúng: slot16 sinh bởi native crypto trong prologue, không phải bytecode-loop. Trace nguồn 0x7a1c0f41d0 = hướng mới (nhưng = memory-watch, chết trên Exynos).

## Lead "pre-computed" — DỨT ĐIỂM (capture đầy đủ nhất): slot16 = custom crypto qua regfile[29]
- slot16 resident @0x7a1c0f41d0 = trong **report header k-v structure** (giữa "X-BD-CONTENT-ENCODING" & "K-VERSION/HOST", key-id 0xc027) = **OUTPUT** đã đặt vào report, KHÔNG phải shortcut. Xuất hiện đúng 1 lần trong 2101 pages.
- **regfile[29]=0x783431ed70 (stack) ratchet buffer = CRYPTO material high-entropy** (`e1b8a4a48410261a…`, `2ff97b5d43dac6e7…`, `abd9831f19cde05b…`, `27fed171e3309259…`). **slot16 KHÔNG phải window của buffer** (raw/^0xed đều miss) — xác nhận lại prior work với capture consistent tốt nhất.
- ⇒ **IRONCLAD: slot16 = custom VM crypto biến đổi ratchet buffer regfile[29] → output đặt vào report.** Không window, không hash đơn giản. Mọi góc (static/unidbg/unicorn/memory) hội tụ: cần reverse custom crypto HOẶC capture/session.

## KẾT LUẬN Đường 2
Pure unicorn-replay: **2/3 obstacle GIẢI** (heap-consistency + invocation-selection = tooling proven). Obstacle #3 (native-call chains qua JIT closures) = **wall custom-crypto cơ bản** — cùng kết luận multi-week của project. Unicorn-replay xác nhận slot16 sinh bởi native crypto (không phải pure-bytecode), củng cố "cần devirt + reverse custom crypto HOẶC A2-hybrid". **A2-hybrid (capture slot16/session) vẫn là đáp án thực tế.**

## Session 6 — 🎯 REFRAME LỚN: obstacle #3 = FRIDA ARTIFACT, KHÔNG phải VM custom-crypto
- **Phát hiện:** captured mem (đọc KHI frida hook active) chứa **frida Interceptor patch** tại 0x52924/0x55950/0xa0748 (`ldr x16,#lit; br x16 → gum trampoline`, verify byte-exact vs .so file) + **gum-trampoline pointers trên stack/regs**. Chuỗi "external linker64/closure" của session 5 = chính là frida gum machinery, KHÔNG phải VM crypto.
- **FIX #1 (un-patch):** sau ghi mem pages, re-write clean .so executable segment từ FILE + re-apply bcFull → xóa frida code-patch. Kết quả: **4 → 2024 blocks**.
- **FIX #2 (gum-cleanup):** replace gum-region pointers (rwxp anon, từ maps) trong stack/regs bằng clean caller. Kết quả: VM function **CHẠY XONG + return SẠCH tới caller 0x9ff1c** (`bl 0x52924`=slot16 VM → đọc w0=[sp+8] → stack-canary check → ret).
- **Còn lại:** VM chạy **17 distinct PCs (short path) → chưa output slot16**. Blanket gum→0x9ff1c làm hỏng giá trị VM dùng (x16 scratch), + caller frame cao hơn (ngoài 16KB stack) còn gum pointer.
- ⇒ **VM computation TÁI TẠO ĐƯỢC offline** — blocker chính là **frida instrumentation pollution**, KHÔNG phải custom crypto. **Đảo ngược kết luận session 4** ("custom-crypto wall"). Pure-offline khả thi hơn nhiều.
- **NEXT (đường rõ):** thay blanket-replace bằng: (a) capture gum trampoline regions + emulate (stub JS-agent-call → resume F+8), HOẶC (b) map từng gum→resume-target đúng (F+8: 0x5292c/0x55958/0xa0750), chỉ clean return-address slots (không scratch regs). Rồi VM chạy full → slot16.
- Tooling: `_correlate_lr.js` (Phase-1), `_vm_singleshot.js` (LR-gate 0x9ff1c + light-BFS), `_enrich_mem.py` (+exec_anon), `_vm_replay_capture.py` (+un-patch +gum-cleanup).

## Session 6 cont — VM replay CHẠY XONG + tính crypto ĐÚNG; 0x9ff1c = report-hash (không phải producer)
- Sau khi xử frida-artifacts, VM invocation (LR=0x9ff1c) **chạy tới epilogue + return sạch tới caller 0x9ff1c** (`bl 0x52924` → đọc w0=[sp+8] → stack-canary check).
- **VM DID CRYPTO (deterministic):** x1 input (pre-VM) = struct con trỏ (`70e93134…, bcd16d37…`); output = **48B high-entropy digest `3a23befadbda7342…`** (VM ghi đè input struct → digest). Reproducible offline.
- **NHƯNG 0x9ff1c = bước HASH structure (X-Argus/report hash), KHÔNG phải slot16-producer:** output digest ≠ mọi captured slot16; capture này không có report-struct (X-BD-CONTENT-ENCODING). Phase-1 correlate nhầm — "invocation cuối trước #19" = report-hash, slot16-compute ở invocation SỚM hơn.
- 🎯 **MILESTONE THẬT: VM computation TÁI TẠO ĐƯỢC offline trong unicorn (deterministic crypto).** Pipeline hoạt động end-to-end. Pure-offline **CHỨNG MINH khả thi** (đảo ngược "custom-crypto wall").
- **NEXT (offline, KHÔNG cần memory-watch/Snapdragon):** **replay-and-match** — capture nhiều VM invocation (các LR khác nhau, hoặc invocation đọc ratchet-buffer regfile[29]), replay từng cái trong unicorn, match output với 1 captured slot16 → xác định ĐÚNG slot16-producer invocation. Rồi invocation đó + input = slot16 offline.

## Đánh giá
Từ "impossible" (note 38, dựa trên frida-hook wall) → **pipeline replay chạy VM thật 12.5M blocks offline**, chỉ chặn bởi 1 diverge last-mile. Passive-root-dump là chìa khóa (user đúng). Crack trọn cần pinpoint diverge (differential trace) hoặc capture-point sạch hơn — **không còn là multi-week devirt**, mà là debug hội tụ.

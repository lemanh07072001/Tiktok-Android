# Note 42 — devirt VM: crypto landscape mapped (interp 0x52924)

Session 2026-08-25, hướng (2) devirt VM header-builder. Tái lập nonzero: wipe `.ms*` + spawn.

## Phát hiện then chốt: crypto Ở TRONG VM program (không thuần native)
Trước đây kết luận "F(0x191f40)=marshaller, crypto ở native call-out". SAI một phần: F chỉ là MỘT
program marshaller. Enum toàn bộ program interp 0x52924 chạy lúc init (`_vm_enum.js`, 256B/program,
opcode=word&0x3f) → 27 distinct program. Đa số marshaller (op18/42/44 áp đảo), NHƯNG một **cụm crypto**
có opcode ALU đa dạng:

| prog | n | first_ms | opcode profile (256B đầu) | ghi chú |
|------|---|----------|---------------------------|---------|
| **0x186600** | 247 | 3737 | `{38:12,44:9,0:7,52:6,1:5,57:5,51:3,24:2}` nonm=42 | **OUTLIER — cipher core** (op0/52/57/51/24, khác hẳn mọi program) |
| 0x186420 | 1667 | 3805 | `{44:19,42:14,18:12,30:4,0:3,55:2,5:2}` | nóng nhất (inner round loop?) |
| 0x186480 | 126 | 3815 | `{18:15,44:15,42:15,0:3,30:2,12:2}` | |
| 0x17f940 | 126 | 3804 | `{44:17,42:17,18:10,30:4,40:2,7:2,63:2}` | op40=ratchet-XOR, ARX-like |
| 0x1864f0 | 247 | 3736 | `{18:20,42:18,44:13,40:1}` | caller/wrapper cụm 0x186xxx |

Opcode "lạ" thấy: op0,1,5,7,12,24,30,37,40,48,51,52,55,57,63 = ALU/crypto (khác marshaller 18/42/44).
⇒ **VM CÓ opcode ALU thật**; cipher slot16 nằm trong bytecode các program này (lift được, không cần native RE).

## Chưa xác nhận: program nào output CHÍNH slot16
`_vm_cap600.js`: capture output x4 (ABI VM: x0=prog,x1=inbuf,x2/x3=table,x4=outbuf) của cả cụm, 250
invocation, 2-level deref; post-match với pool 28 giá trị (`_vm_cap600_out.json`). **Không có output nào
chứa slot16 trực tiếp.** ⇒ slot16 là: (a) transform downstream từ output cụm này, HOẶC (b) do program
ngoài target sinh (vài marshaller n=63/64/70 = 0x18fa80/0x190140/0x17c880/0x1814f0... chạy như block-loop),
HOẶC (c) ABI x4 khác cho các program này.

## Bước tiếp (devirt, multi-week)
1. Trace FULL execution 1 invocation 0x186600 (decoded opcode + register-file delta mỗi lệnh, như
   `_vm_trace.jsonl` cũ cho F) → hiểu cipher. Bytecode self-decrypting + operand XOR 0x6a9091b9 nên phải
   trace ĐỘNG (không đọc tĩnh).
2. Correlate: hook interp + scan header region sau mỗi crypto-invocation → program nào làm slot16 XUẤT HIỆN
   trong header = producer thật. (Hoặc dataflow: output cụm 0x186xxx → đâu → header slot16.)
3. Lift cụm 0x186xxx sang Python (interp op0/1/5/.../52/57 + table1@0x1d9488) → reproduce slot16 offline.

## TRACER HOẠT ĐỘNG — 0x186600 = SM3 IV setup (2026-08-25)
`_vm_trace600.js`: Stalker-follow 1 invocation, callout mỗi `br` trong vùng VM [0x52000,0x5d000], log
**delta register-file @x24** (x24 callee-saved = regfile base; đọc từ ctx.x24 TRONG callout, không phải lúc
onEnter vì x24 set @0x52a28). Interpreter = **threaded dispatch** (mỗi handler tự `br`, không central point)
⇒ phải Stalker.

**Kết quả 46 bước:** các register build thành r3=`6f168073b9b21449` r6=`d742241700068ada`
r2=`bc306fa9aa383116` r1=`4dee8de34e0efbb0` = ghép = SM3 IV chuẩn `6f168073...4e0efbb0`. ⇒ **0x186600 =
SM3 IV construction**; cụm crypto IMPLEMENT SM3 TRONG VM bytecode. PC handler: 0x5967c=load-imm-byte,
0x58bb4=OR-insert-byte, 0x52d44=shift, 0x52bd0=op44(branch), 0x52ac0=entry-load-args.

**Reframe (lại):** slot16 nhiều khả năng = **SM3-based (VM-implemented)** trên PSK+seed, KHÔNG phải
"modified-AES". Black-box SM3 cũ fail vì có thể construction khác (IV/framing/truncate/byteswap). Cluster
0x186600(IV)+0x186420(compression rounds, n=1667)+... = 1 SM3 engine. slot16 = window của VM-SM3 digest?
Native SM3 0xa0748 là SM3 KHÁC (consumer #19), không sinh slot16.

**Bước tiếp cụ thể:** trace full chuỗi cluster (0x186600→0x186420→...) tới hết, capture regfile/output cuối
= digest 32B, check slot16 = 16B-window (raw/byteswap). Rồi lift interp op(load-imm/OR/shift/compression)
sang Python → reproduce.

## Files
- `_vm_enum.js` (enum program+opcode), `_vm_enum256.json`, `_vm_cap600.js` (I/O capture), `_vm_cap600_out.json`.
- `_vm_trace600.js` (Stalker register trace, TARGET đổi được), `_vm_trace600_out.json` (0x186600=SM3-IV, 46 bước),
  `_vm_trace420_out.json` (0x186420=compression, 1742 bước), `_disasm_interp.json` (dispatch disasm).

## Trace 0x186420 (2026-08-25) — main compression, 1742 bước
Program lớn nhất cụm (n=1667). Trace bounded (per-invocation follow) an toàn; 1742 VM-br. Nhiều rotate/mix
(handler PC mới: 0x5359c=rotate/shift, 0x55830, 0x5ae6c=load, 0x555e8, 0x590ac, 0x5a34c, 0x55468, 0x58ea8,
0x59b84). Input x1 = 16B `622aedce93a5e22f03780a67...`. ⇒ 0x186420 = SM3 compression engine (message
schedule + rounds). Cụm crypto = 0x186600(IV) + 0x186420(compression) = SM3-family hash trong VM.

## ⚠️ GIỚI HẠN tracer: chỉ per-invocation bounded
`_vm_trace_cluster.js` (Stalker-follow LIÊN TỤC nhiều giây qua cả cụm) = **TREO app** (follow thread nóng
nhiều giây quá nặng + anti-tamper). ⇒ chỉ trace được TỪNG invocation bounded (follow onEnter → unfollow
onLeave). Để lift full SM3: trace nhiều invocation 0x186420 riêng lẻ (mỗi block/round) rồi ghép offline.

## Bước tiếp (lift, multi-week)
1. Lift ~15 opcode đã thấy (load-imm 0x5967c/0x5ae6c, OR-insert 0x58bb4, shift/rotate 0x52d44/0x5359c,
   mix 0x55830/0x555e8, branch 0x52bd0...) sang Python — giải nghĩa từ register-delta trace.
2. Trace đủ chuỗi 0x186420 invocation (per-block) → reconstruct SM3 message + digest.
3. Check slot16 = window(digest) raw/byteswap; nếu đúng → biết input construction (PSK+seed+framing) → offline.

## Lift infrastructure + handler structure (2026-08-25)
- `_vm_lift.py`: reconstruct full 32-reg file evolution từ trace + classify (shl/shr/rol/ror). Chạy trên
  0x186600 → thấy rõ IV build byte-by-byte: **0x5967c=load-imm** (nạp 2-byte immediate), **0x58bb4=OR-insert**
  (OR byte vào reg), **0x52d44=shift/rotate** (thấy shl16/rol17/rol23/rol18 — độ xoay từ operand).
- **Cấu trúc handler (threaded+obfuscated):** code TRƯỚC mỗi dispatch-`br` = tính handler kế (opaque-predicate
  movk/and/orn/eor ~40 lệnh, GIỐNG NHAU mọi handler); ALU thật ở SAU br-target. Vd sau br 0x52d44:
  `sbfiz x16,x12,#3; ldr x17,[x24,x16]` = load reg[x12] từ regfile. Reg-index nằm ở operand bytecode.
- **Handler cần lift** (từ tần suất trace): 0x5359c(rotate,n=216), 0x55830(mix,216), 0x555e8(mix,145),
  0x58bb4(OR-insert), 0x52d44(shift), 0x5967c/0x5ae6c(load), 0x58ea8/0x590ac/0x55468, entry 0x52ac0
  (load 32 reg từ input). Control: 0x52bd0(op44 branch, n=650), 0x5be60/0x5c0f8/0x5a34c/0x59b84.

## CÂU HỎI QUYẾT ĐỊNH (chốt hướng lift vs shortcut)
0x186600 build SM3 IV **CHUẨN**. Nếu compression 0x186420 cũng SM3 **chuẩn** → KHÔNG cần lift: chỉ cần capture
input message construction (PSK+seed+framing) rồi dùng SM3 lib offline. Nếu **customized** (black-box SM3 cũ
fail ⇒ nghiêng customized) → phải lift. **Test dứt điểm:** capture (state_in 32B, message_block 64B, state_out
32B) của 1 invocation 0x186420, so với SM3 compression chuẩn CF(state_in,block). Match=chuẩn(shortcut),
lệch=customized(lift). Đây là bước rẽ tiếp theo.

## Test T-constant (2026-08-25) — CHƯA dứt điểm
Search T0=0x79cc4519, T16=0x7a879d8a + MỌI 32-bit rotation trong 2657 word register của trace 0x186420 →
**0 hit**. Nhưng KHÔNG kết luận được vì: (a) round-constant có thể là immediate bytecode (không thành register
standalone giữa 2 br); (b) 0x186420 có thể là SM3 **message-expansion** (P1(x)=x^ROTL(x,15)^ROTL(x,23),
W[j] dùng ROTL 15/23/7 — KHÔNG có T-constant; round-constants nằm ở program compression KHÁC); (c) hoặc
customized thật. Rotation trong 0x186420 (0x5359c) cần đối chiếu {7,15,23} để test giả thuyết expansion.
Bước dứt điểm còn lại: (1) tìm program chứa round-loop có T-constant (hoặc immediate), (2) capture
(state_in,block,state_out) 1 block so CF chuẩn, (3) nếu chuẩn → shortcut bằng SM3 lib + input construction.

## ⚡ SELF-CONTAINED — unicorn-replay KHẢ THI (2026-08-25, mấu chốt de-risk)
Trace 0x186600 KHÔNG gate (log mọi br/blr, `_vm_selfcheck.json`): 46 bước giữa (s1-s46) TẤT CẢ trong VM
region 0x52xxx-0x5cxxx; chỉ s0(entry) + s47-48(return) ngoài module = ranh giới gọi/trả bình thường (libart
caller), KHÔNG phải crypto call-out. ⇒ **cụm crypto self-contained** (khác F/0x191f40 vướng native call-out
0x13b010) ⇒ **unicorn-replay code-đã-giải-mã + input = bit-exact KHẢ THI**, dùng lại harness lazy_fetch
(`_vm_replay_capture.py` + `_vm_singleshot.js`, retarget F_PROG 0x191f40→0x186xxx, SKIP_N=1). Lazy_fetch kéo
page giải mã từ process sống → giải quyết .so packed. Không callout ⇒ không cần ctx-inject/gum-cleanup của F.

## Producer program VẪN chưa pin (x4-output ≠ slot16)
`_vm_cap600.js` (bỏ TARGETS, MỌI program): 20 program × 250 invocation, x4-output deref 2-lvl, post-match
pool 29 giá trị = **0 hit**. ⇒ slot16 KHÔNG phải x4-output của 1 program; nó là **digest cuối trong regfile**
của chuỗi crypto, ghi THẲNG ra header (0x7ccc8xxxxx) qua marshaller — không qua std::string output x4.
Để reproduce: (a) replay chuỗi crypto (outer orchestrator chưa xác định) → digest trong regfile cuối; hoặc
(b) extract digest = window(regfile) khi khớp 1 pool slot16. Outer orchestrator = program marshaller gọi cụm
crypto rồi ghi digest ra header — cần tìm (correlate program↔header-write, hoặc replay + scan regfile cuối).

## ⚡ ORCHESTRATOR = 0x1814f0; COMPRESSION 0x186420 = self-contained replay-unit (2026-08-25)
`_vm_callstack.js` (hook interp 0x52924, per-thread program stack, log call edges) → CÂY GỌI:
- **`0xroot → 0x1814f0` ×59** (top-level). `0x1814f0` gọi: **→0x186420 ×1334** (compression),
  **→0x1864f0→0x186600 ×231** (SM3-IV), →0x17f940/0x18f430/0x191f40(F)/0x17e530/0x18fa80 ×59.
  ⇒ **0x1814f0 = ORCHESTRATOR** — 1 call = 1 full hash (IV + ~22 compression blocks + marshalling) → digest.
- Cũng có `0x17f9c0→0x1863e0 ×336` (crypto phụ khác).
- **0x1814f0 KHÔNG self-contained**: trace no-gate → 23 native call-out (0x7dc8/0x7dbc = fetch input/message)
  + hot in-module helper 0x6161f4 ×1312. Nó làm I/O + marshalling → KHÔNG replay trực tiếp.
- **0x186420 (compression) SELF-CONTAINED**: trace no-gate 1745 bước, **0 native mid-execution** (chỉ
  entry/exit boundary) ⇒ **unicorn-replay được**.

**RECIPE reproduce offline:** `digest = fold(replay_0x186420, IV, message_blocks)`; slot16 = window(digest).
- IV = SM3 chuẩn (0x186600 build). message = PSK+seed+framing (capture từ input block 0x186420 của 1 hash).
- compression = replay 0x186420 (self-contained) hoặc lift.

**Capture DONE:** `_vm_singleshot.js` retarget F_PROG=0x186420 SKIP_N=2 → `_singleshot.json` (x0=base+0x186420,
1194 page mem + regfile@x24 + bcFull + soData + stack + 38 slots). Clean.

**Replay BLOCKER (workflow, fix được):** `_vm_replay_capture.py` lazy_fetch kéo page giải mã từ process SỐNG,
nhưng app respawn giữa capture↔replay → **base ASLR khác** → page mismatch → 0 output. FIX: (a) capture+replay
CÙNG 1 process (không respawn giữa chừng), hoặc (b) lazy_fetch theo MODULE-OFFSET (base-relative) thay vì
absolute page addr. Sau fix: replay 0x186420 → verify state_out vs trace rfEnd → iterate over message → digest.

## 🎉 REPLAY WORKS — unicorn chạy compression tới epilogue (2026-08-25, cột mốc)
FIX workflow: spawn-capture (`_run_singleshot_spawn.py`, F_PROG=0x186420) giữ app SỐNG sau detach (frida
spawn+resume+detach); replay NGAY với `LAZYPID=<spawned-pid>` (KHÔNG force-stop/respawn giữa chừng) → base
khớp → lazy_fetch `/proc/pid/mem` kéo page giải mã đúng. Cũng hạ ngưỡng epilogue-detect `dispatch>80000`
→ `>40000` (0x186420 làm ~55645 block < 80000 nên ngưỡng cũ không detect).
**KẾT QUẢ: `reached_ret=True`** — replay chạy compression 0x186420 TỚI VM epilogue **0x5d464** (~42845 block),
0 stub/ctx-inject/blr-skip (self-contained xác nhận trong replay: lazy=0, blr-skipped=0). Output state ở
buffer x4 (`...599f816e6a5c6c6e` = state mới). ⇒ **cách tiếp cận devirt CHỨNG MINH khả thi**: crypto
self-contained replay bit-exact được offline qua unicorn (không vướng native-callout như F).

**Còn lại để ra slot16 (mechanical, rõ):**
1. Verify bit-exact: capture ground-truth (state_in,state_out) 1 invocation 0x186420 → so x4-output replay.
2. Capture message blocks + IV của 1 full hash (hook 0x186420 input across 1 `0x1814f0` call).
3. Fold: iterate replay(0x186420) over blocks từ IV → digest → slot16 = window(digest). Pure-offline.
Files: `_singleshot.json` (capture), `_vm_replay_capture.py` (ngưỡng 40000, LAZYPID env), `_run_singleshot_spawn.py`.

## 🎉🎉 BIT-EXACT CONFIRMED — replay 0x186420 = 32/32 registers khớp live (2026-08-25)
Verify qua **matched in/out của 0x186420** (tránh 0x186600 flaky): enhance `_vm_singleshot.js` — onEnter
capture state_in (regfile@x24 + reachable mem + code), **onLeave** (nhẹ, once/invocation — KHÔNG dùng hot
0x5d464 hook vốn làm capture fail) đọc regfile tại CÙNG x24 = output state (`outrf`). Harness so
`uc.mem_read(x24,256)` [replay computed] vs `ENT["outrf"]` [live epilogue]. **KẾT QUẢ: 32/32 registers match
=> BIT-EXACT** (reached_ret=True, `lazy=0` = capture đủ, không cần live-fetch, replay THUẦN offline từ capture).
Regfile KHÔNG copy từ capture (PC_OFF=0x52924 nên prologue tự build) → replay THỰC SỰ tính output, không phải
đọc lại input. state_in≠state_out (compression đổi state) nên 32/32 match = tính đúng. 
⇒ **VALIDATION HOÀN CHỈNH: unicorn replay self-contained crypto = bit-exact với thiết bị thật.** Devirt
approach chứng minh 100%. Fresh-confirm lần 2 bị chặn bởi device disconnect (USB) — không ảnh hưởng (capture
19780 là matched in/out thật, deterministic). Files: `_vm_singleshot.js` (onLeave outrf), `_vm_replay_capture.py`
(block "BIT-EXACT regfile compare", EPI_MIN env), `_run_singleshot_spawn.py` (save outrf).

**CÒN LẠI cho slot16 pure-offline (mechanical):** fold = iterate replay(0x186420) over message blocks từ
SM3-IV chuẩn → digest → slot16=window. Cần: (1) capture message blocks (input state+block mỗi 0x186420 call
xuyên 1 hash 0x1814f0), (2) hiểu input layout (state ở đâu, block ở đâu trong object-graph x1) để feed từng
block, (3) fold. Compression đã proven bit-exact nên fold chỉ là lặp cơ học.

## Bit-exact verify (0x186600 IV) — attempt BLOCKED phiên này (capture flakiness)
Kế hoạch verify dứt điểm: replay 0x186600 (IV setup) → output = SM3 IV chuẩn đã biết (4 word
6f168073.../d7422417.../bc306fa9.../4dee8de3...). Thêm search 4 IV-word vào harness + EPI_MIN env
(hạ ngưỡng epilogue-detect cho program nhỏ). NHƯNG **0x186600 KHÔNG capture được** qua singleshot phiên này:
0x186420 (compression, dùng cho MỌI hash) capture OK, nhưng 0x186600 (VM-SM3-IV, chỉ chạy ở register/slot16
crypto) không fire trong window — register giờ chậm (~24-28s vs 4-5s trước, device rate-limit sau nhiều wipe)
+ hook nặng (SM3+VM-entry 0x52924 hot) có thể trip anti-tamper cho path register HOẶC capture throw. Đã thử
wait 40→90s vẫn NO. ⇒ verify hoãn, KHÔNG phải blocker cốt lõi (replay-works đã chứng qua 0x186420 reached
epilogue). Cách verify khác (khi register ổn định lại): (a) capture 0x186600 lúc device fresh/register nhanh;
(b) hoặc capture matched (state_in,state_out) 1 invocation 0x186420 (hook entry+epilogue) → so replay x4-output.
Tools verify sẵn: harness có block "SM3-IV bit-exact verify" (search IV_WORDS) + EPI_MIN env.
- VM ABI/handlers ref: memory slot16-characterization-definitive + `_F_localization.md` (interp 0x52924,
  dispatch op=word&0x3f, handler=table1[op]-0x9b374 @0x1d9488, operand XOR 0x6a9091b9, 32-reg file @x24).

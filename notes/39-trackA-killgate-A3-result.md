# 39 — Track A kill-gate (A3 determinism) RESULT (2026-08-24)

> Nối [[36-2A-pure-offline-roadmap]] §7/§91, [[34-slot16-analysis]], [[38-slot16-three-walls-consolidated]].
> Trả lời câu hỏi GATE: nonzero slot16 **tất định từ state local + input biết được** (lifter Track A khả thi)
> hay **trộn entropy per-request không tái tạo** (Track A chết)? Chạy 6-agent workflow (offline, binary +
> data đã capture; 284K token). **ĐỌC PHẦN "HỢP NHẤT VỚI NOTE 38 + KẾT LUẬN ROI" Ở CUỐI TRƯỚC.**

## Verdict cuối: **UNPROVEN — de-risk BẮT BUỘC trên phone TRƯỚC khi viết lifter.** (KHÔNG commit multi-week vội.)
- Synthesis: `DETERMINISTIC_TRACK_A_VIABLE` conf **0.82** (dựa static).
- Adversarial: verdict **KHÔNG sống sót**, hạ **0.55**. Lý do: static chỉ chứng minh **VM là hàm thuần của SEED**;
  **provenance của SEED (sign() nạp gì TRƯỚC khi vào VM) CHƯA soi**, và cntvct **reachable trong sign()**.
  Test hành vi duy nhất (E4 stable-query) **THẤT BẠI** (query cố định + keva y hệt vẫn ra slot16 khác mỗi call).

## Bằng chứng static (E1+E2) — VM interpreter SẠCH entropy (mạnh)
- **E1 (FOR)**: map delta=0 (file-off==vaddr; verify MD5 IV @0x15b594, SM3 prologue @0xa0748).
  - **KHÔNG có getrandom** ở đâu cả — `0x116` chỉ xuất hiện dạng hằng-32bit `mov w8,#0x116` trong VM opcode math, KHÔNG phải `x8` syscall. Time-syscall (169/113/114/153/101/115/165) cũng chỉ là hằng w8, không svc.
  - **VM region 0x55890–0x5c000 cô lập cấu trúc**: 0 svc byte + 0 `bl`/`b` ra ngoài region (soi 27458 bl + 8583 b edges; reach từ 0x55950/0x55890/0x5b8fc = 1-2 fn, không fn nào chứa svc). Interpreter tự chứa → KHÔNG thể chạy syscall / nhận entropy qua call. Input được sign() nạp sẵn vào memory TRƯỚC khi vào VM.
  - Primitive nondeterministic DUY NHẤT = 4× `mrs Xd, cntvct_el0` @0xc2294/0xc22e8/0xc2378/0xc23cc, đều trong **1 cụm anti-tamper/timing ~0xc2280** (chạy statx(291)/newfstatat(79)); giá trị vào scratch reg (đo thời lượng syscall = anti-debug), **reachable từ sign() nhưng KHÔNG từ VM region**.
  - Syscall thật resolve được gần svc: newfstatat(79)×10, statx(291)×10 (cụm anti-tamper), clone(220)×2. 156-171 svc là "gateway tail" x8-qua-reg (obfuscated br x1/x15) không resolve tĩnh — nhưng không reach vào VM/slot16 region.
- **E2 (FOR)**: op40 @0x5b8fc disasm trực tiếp — XÁC NHẬN mechanic note cũ:
  `new_r29 = old_r29 ^ 0x0a123f43` (hằng), self-modify `mem[old_r29*off+off] ^= 0xed` với `off=sxth([sp,#0x70]&0xffff)`; x25 (reg index) advance từ opcode stream (`x25=op>>27; x25^=0x4a5cabc9`). `reads_external_input=none`, `vm_entry_pulls_entropy=false`. Full-scan VM region mrs/svc/msr = **0 hit** (không CNTVCT/PMCCNTR/syscall/MSR). mrs duy nhất trong sign path (0x9ecd4, 0x8dfe8/0x8e150/0x8e3c4) = `tpidr_el0` stack-canary, KHÔNG vào slot16.
  - ⇒ ratchet = **hàm thuần của (seed regfile/VM-mem ban đầu + bytecode + step count)**. Reframe kết luận note 45 ("không reproduce từ static input") = vấn đề **SAI seed / sai step-count**, KHÔNG phải nondeterminism.
  - ⚠️ Caveat E2: tất định **có điều kiện** biết đúng (a) seed regfile/VM-mem ban đầu, (b) đúng số bước opcode. Self-modifying byte-patch ⇒ trạng thái memory **path-dependent** cả VM run.

## Bằng chứng data (E3+E4) — NEUTRAL (undersampling, không phải AGAINST)
- **E3 (NEUTRAL)**: `_a1_vmcap.json` capture ở **SM3-leaf frame** (0xa0748), regfile ở **frame CAO HƠN chưa capture** → regfile[29] không đọc được ở đây. Nhưng bắt trực tiếp buffer slot16-class 16B (SM3 input riêng): **entry1 nonzero=`3bcb9b9cce285189eecc39e608182ac0`** (heartbeat/logged-in), **entry5 zero=`00..00`** (business-API) → khớp fact "slot16=0 cho ~40% business". Chỉ 1 mẫu nonzero → không test được ratchet-evolution. entry0/2 share 64B query prefix nhưng khác tổng-len (680 vs 697) → KHÔNG phải same-query.
- **E4 (NEUTRAL)**: 34 record (19 nonzero). Per-byte entropy 4.14–4.25 bit → hash-like uniform. **Stable-query test THẤT BẠI**: query cố định + keva y hệt (ecneuq=94199bca6d60ed2e, semithc=06c89feae2d013cceab9ad17) vẫn ra slot16 KHÁC mỗi call (heartbeat 3/3 distinct, empty-prefix register 11 distinct). slot16 **biến theo _rticket** (avalanche: 671771→..77, 672070→..3f, cách 299ms → đổi hoàn toàn). **0 recurrence** — không thấy grid 270000ms. tikcast_stable = 1 mẫu **chưa verify** (không có capture thứ 2).
  - QUAN TRỌNG: dataset **KHÔNG hề có** ca same-input→different-output; mọi output ứng _rticket khác nhau — hợp với **PRF tất định trên (query+_rticket+state local)**. Nhưng cũng KHÔNG có repeat/same-query để chứng minh dương.

## Kênh entropy adversarial nêu (chưa loại) — soi ở de-risk
1. **cntvct trong chính sign()** (cụm 0xc2280) gập vào SEED nạp cho VM — reachable từ sign(), chỉ loại khỏi VM region, nên **taint seed KHÔNG cần call-edge vào interpreter**.
2. mrs CNTVCT/PMCCNTR ẩn sau br x15/x1 (156-171 gateway x8 không resolve tĩnh).
3. **ASLR pointer-as-entropy**: op40 patch `mem[r29*off+off]` (địa chỉ từ state); nếu 1 word regfile ban đầu là con trỏ stack/heap/mmap → slot16 nondeterministic **theo launch** (ổn định TRONG session → giả dạng "avalanche theo _rticket"). regfile[29] chưa đọc được (E3).
4. **Uninitialized VM/heap mem** (malloc thay vì calloc) → byte-patch từ rác heap; vô hình với mọi scan getrandom/string/syscall.
5. Thread/TLS jitter / per-call counter nạp bởi sign() → distinct output trên cùng (query,keva) đúng như E4 thấy, không dấu vết syscall.

## DE-RISK QUYẾT ĐỊNH (làm TRƯỚC lifter; ĐỒNG THỜI = A1-recapture lifter cần)
Re-capture ở **frame op40 0x5b8fc / VM-entry 0x55950** (KHÔNG phải SM3-leaf) để dump **VM regfile + regfile[29] + SEED sign() nạp + slot16**, gated cho 1 sign nonzero. Kiểm:
- (a) **Seed provenance**: seed chỉ gồm giá trị biết được (PSK-derived + query/_rticket/keva) hay có word = cntvct (counter khổng lồ đơn điệu) / con trỏ ASLR (0x7x..) / rác uninit? ← đây là chỗ adversarial nói CHƯA soi.
- (b) **same-seed → same-slot16?** (bắt seed_in + slot16_out nhiều sign; nếu cùng seed relevant → cùng slot16 = xác nhận hàm thuần).
- (c) Dynamic: hook getrandom(0x116) + cntvct trong 1 sign nonzero → 0 call trên đường slot16 (xác nhận động cái static E1).
- Cross-launch: nếu seed chứa con trỏ ASLR → slot16 đổi qua restart app với input y hệt → ASLR entropy (dead cho pure-offline; nhưng vẫn A2-hybrid được).

**GATE**: seed toàn giá-trị-biết + same-seed→same-slot16 + getrandom 0 call ⇒ **DETERMINISTIC → build lifter**. Nếu seed có cntvct/ASLR/uninit không tái tạo ⇒ **Track A pure-offline chết → A2-hybrid** (phone-oracle slot16/session, đã proven).

## Lập luận lý thuyết ủng hộ tất định (yếu, cần verify)
Server phải verify được #19=SM3(query‖slot16‖0x30). Nếu slot16 phụ thuộc entropy local server không biết (cntvct/ASLR) thì server KHÔNG verify được → slot16 nhiều khả năng = f(input server thấy được: query/_rticket + PSK session + device-state đã register). *Caveat: chưa biết server RECOMPUTE hay chỉ store/correlate #19.*

## Trạng thái
- Kill-gate làm xong bước bounded phiên này. Kết: **VM sạch (chắc), nhưng end-to-end determinism CHƯA chứng minh — seed-staging là khoảng trống.** Không commit lifter. Bước kế = de-risk capture ở frame VM (phone), vừa gỡ gate vừa lấy seed cho lifter.
- Artifact workflow: `tasks/wszhbxvmc.output` (6 agent, full verdicts).

## HỢP NHẤT VỚI NOTE 38 + KẾT LUẬN ROI (đọc kỹ — thay đổi giá trị Track A)
Kill-gate này KHỚP & làm chặt note [[38-slot16-three-walls-consolidated]] (session trước). Cùng chốt về **1 vật thể**:
buffer **regfile[29] ratchet** (RAM-only). Note 38 đã có capture VM-frame thật (`captured_data.json`, 40 vm_entry_v3
@0x55950, base=0x6f5fe00000, có regfile 256B + bytecode256), nhưng **NỘI DUNG buffer mà regfile[29] trỏ tới =
CHƯA capture** (deref = access-violation); `regfile[29]=0x6f276e73c0` (con trỏ heap DƯỚI .so base).

**Kill-gate đóng góp MỚI:** nâng "unicorn 0x55950 feasible" (note 38 loose) thành **chứng minh call-graph chặt**
(E1: VM region 0 svc + 0 bl/b ra ngoài trên 27458 bl/8583 b edges; E2: ratchet thuần số học). ⇒ VM = hàm thuần
của seed. Câu hỏi viability co lại **đúng 1 điểm = provenance của buffer regfile[29]**.

**KẾT LUẬN ROI (trung thực, quyết định chiến lược):**
1. **Pure-offline (KHÔNG BAO GIỜ cần phone) = bất khả** — tái xác nhận (note 38 Tường 1+2: không công thức tĩnh,
   unidbg không provision được PSK). Muốn pure-offline phải tái tạo seed buffer offline; seed = RAM-only, không
   trong store, không provision được. Adversarial còn thêm rủi ro ASLR/uninit ở lúc provision.
2. **Track A lifter (multi-week) — kể cả CHẠY ĐƯỢC — vẫn cần 1 live-capture buffer / session** (buffer chỉ có
   trong RAM sống của session). ⇒ **KHÔNG loại được phone; KHÔNG hơn A2-hybrid** ở đúng metric người dùng cần
   (phụ thuộc phone). A2-hybrid đã PROVEN: slot16=0 cho ~40-50% (business) → offline sẵn; nonzero (register/
   heartbeat, hiếm, ~1 lần/session) → hook SM3 nhẹ capture 1 lần/session.
3. Full-no-phone vẫn chặn độc lập ở device-trust/Widevine (lỗi 7) — Track A không đụng tới.

⇒ **Track A multi-week lifter = ROI thấp**: không pure-offline được, nên không thắng A2-hybrid về phone-dependency,
và không mở full-no-phone. **Khuyến nghị: DỪNG Track A, dùng A2-hybrid production cho nonzero slot16.**

**Thí nghiệm bounded DUY NHẤT còn đáng cân nhắc (Path-B, note 38 §45 "chưa chứng"):** capture nội dung buffer
regfile[29] 1 lần + test unicorn replay → nếu ra đúng slot16 ⇒ "capture-1-lần/session → replay offline mọi
request". Nhưng đây vẫn = 1 capture/session (≈ A2-hybrid) + tốn công gỡ instrumentation-wall (hook 0x55950
772×/sign hang). Cách mới có thể thử: gate dump CHỈ 1 lần + đọc buffer qua con trỏ regfile[29] (không hook nóng).
Payoff cận biên trên A2-hybrid. **Cần người dùng quyết có đáng làm không.**

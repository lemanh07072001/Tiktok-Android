# Note 44 — slot16 F: black-box ĐÓNG CỬA DỨT ĐIỂM + reconciliation note 42↔40

Ngày 2026-08-25. Phiên Fork A ("hoàn thiện fold slot16"). Hai kết quả then chốt.

## A. RECONCILIATION: "fold 0x186420" (note 42) ĐUỔI NHẦM HÀM

Note 42 kết luận `slot16 = window(fold(replay_0x186420, IV, message))` và ăn mừng "bit-exact 32/32".
Kiểm tra lại trên device live (`_fold_capture.js`, spawn fresh, hook `0x52924` lọc `0x186420`, 76 call/3 orch):

- **0x186420 KHÔNG bắt đầu từ SM3-IV** — không có chữ ký `6f168073`/`7380166f` trong BẤT KỲ buffer nào.
- **q1 (x1[1]) = report protobuf STREAMING**, con trỏ tiến +0x10 mỗi call:
  `...31323333320a32313432383430353531 3a0634352e352e34 42147630352e30322e30372d6f762d616e64726f6964...`
  = "12332\n214284055 :\x06 45.5.4 B\x14 v05.02.07-ov-android" → đây là REPORT BODY đang được hash.
- **PSK ở x1+0x30 (48B) làm KEY cho mọi call** (`b2a9d40c...` device này).
- ⇒ `0x1814f0→0x186420` = **HASH REPORT BODY** (X-Argus report MAC), KHÔNG phải slot16-producer.
- "bit-exact 32/32" của note 42 so `regfile@x24` — mà regfile này = **con trỏ, KHÔNG đổi qua compression**
  (`regfile==outrf` byte-identical trong `_singleshot.json`). ⇒ verify đó **vacuous cho crypto** (chỉ chứng
  con trỏ VM giữ nguyên, không chứng state SM3 tính đúng). Note 42 tự thừa nhận "producer chưa pin / x4-output
  ≠ slot16 / 0 hit" — khớp hoàn toàn với kết luận này.

**Nguồn luật đúng = note 40 (DEFINITIVE):** `slot16 = F(PSK 32B, seed 4B) → 16B`, F là hàm THUẦN xác định
(cache-wipe tái tạo y hệt), "modified cipher", **upstream & tách biệt** cả 2 SM3 (native #19 @0xa0748 và VM
report-hash 0x186420 chỉ CONSUME slot16 đã nhúng sẵn trong message `query‖slot16‖'0'`).

## B. BLACK-BOX F: ĐÓNG CỬA (thêm Simon/Speck/SM4 vào danh sách đã-loại)

Ground truth = `_corr_data.json` (13 cặp `{seed 4B, slot16 16B}`, PSK cố định
`c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163`). slot16 = 16B = **1 block 128-bit**.

Kỹ thuật mạnh hơn brute-forward: **decrypt-and-look** (giải mã 13 slot16 với key ứng viên → seed có xuất hiện
nhất quán ở 1 offset, phần còn lại CONSTANT không?) + **seed-as-key** (13 slot16 giải mã ra CÙNG 1 block?).

| Cipher | KAT | (A) decrypt-and-look | (B) seed-as-key | Kết quả |
|---|---|---|---|---|
| AES-128/192/256 (ECB) | lib | no seed-exact, no lowvar | no const-block | MISS |
| SM4 (raw block, tự impl) | OK (681edf34…) | no | no | MISS |
| Speck128/128,192,256 (be+le, k-order) | OK (a65d9851…) | no | no | MISS |
| Simon128/128,192,256 (be+le, k-order) | OK (49681b1e…, lib) | no | no | MISS |

Key ứng viên đã thử: PSK32, PSK16lo/hi, PSK24, embedded `@0x19b520` (32B), `.data@0x960` (5×16B),
`.rodata@0x17baa0` (2×16B). seed-expansion: seed×4/×8, seed‖0, seed‖PSK, PSK‖seed.

**Cộng dồn note 40** (MD5/SHA1/SHA256/SM3/HMAC mọi thứ tự; AES ECB/CBC/CTR mọi key×block; keystream
SM3/AES-CTR 36k; hash-chain/ratchet; sandwich SM3) → **mọi primitive chuẩn 128-bit + lead Simon = LOẠI.**

⇒ **F = primitive TÙY BIẾN trong VM** (op40 ratchet self-modifying `^0xed`, operand XOR `0x6a9091b9`,
dispatch-bias `0x9b374`). Không đoán được. Con đường DUY NHẤT ra pure-offline slot16 = **LIFT F từ VM**
(trace + replay đoạn F, như đã làm với 0x186420 nhưng nhắm ĐÚNG handler F). Đây là frontier multi-week
(note 40 P1 / note 43), KHÔNG "cơ học/gần xong" như Fork A tưởng.

## Hệ quả cho Fork A ("register offline sau capture 1 lần")
- **Pure-offline nonzero-slot16**: cần lift F (frontier). Black-box đã đóng, không phí công đoán thêm.
- **A2-hybrid** (capture cặp (seed,slot16), reuse offline): HỢP LỆ vì slot16 ĐỘC LẬP query (chỉ PSK+seed);
  server verify slot16==F(PSK,seed) theo seed client gửi → reuse cặp đã bắt sẽ pass (seed non-monotonic,
  slot16 reuse ~6.3h). Cần: (1) vị trí seed/slot16 trong request, (2) report-protobuf assembly (track khác).
- **Request thường**: đã pure-offline (slot16=0).

## C. LIFT-F attempt (2026-08-25, sau reboot): 0x191f40 LOẠI làm producer

Reboot device (fix frida-spawn hỏng). Verify F=0x191f40 (note-40 claim) RIGOROUSLY:
- `_f_verify.js`: hook 0x191f40, đọc output x4 = **object(vtable `40001fd6`=blr + pointers), KHÔNG phải
  std::string slot16**; in_x4==out (không đổi). poolHit=null cả 8 call.
- `_vm_trace600.js` (TARGET=0x191f40): trace 1014 bước, **33 handler đa dạng** (0x555e8=mix, 0x5ae6c=load,
  0x58bb4=OR-insert, 0x5967c=load-imm) + **SELF-CONTAINED** (3 native br=entry/exit). ⇒ enum cũ "0x191f40=
  marshaller {42:33,18:26}" SAI (chỉ sample 256B prologue); **0x191f40 THỰC SỰ làm crypto ops**.
- **NHƯNG output ≠ slot16**: check MỌI 16B window regfile (2 trace, raw+byteswap+swap) vs pool 36 giá trị
  device-stable = **0 MATCH**. onLeave của 0x191f40 KHÔNG fire (đúng cảnh báo "giant VM không return cleanly").
- ⇒ **0x191f40 = crypto program nhưng KHÔNG phải slot16-producer.** Loại. (note-40 "F=0x191f40" chưa từng
  verify output=slot16 — cùng lớp lỗi 0x186420.)

## CRUX chưa giải: slot16-producer VẪN chưa định danh đúng
Mọi VM program đã thử (0x186420=report-hash, 0x191f40≠slot16, cả cụm 0x1866xx cap x4=0 hit) ĐỀU fail verify.
2 khả năng: (a) producer = **native CFF code** (session này thấy slot16 ghi bằng direct-str trong code obfuscated
0xa0xxx, KHÔNG qua VM program sạch), (b) VM program chưa tìm ra. **Bài học kép: KHÔNG lift bất kỳ candidate nào
tới khi VERIFY output=slot16 thật.** Bước đúng tiếp = định danh producer bằng cách bắt slot16 lúc SINH (verified),
KHÔNG đoán program. Đây là bức tường lặp lại của project (SW-watch production-before-arm + Exynos no-HW-wp).

## E. STORE-trace 0x17c880 (claude) → LOẠI luôn candidate cuối
Codex nêu 0x17c880 = ứng viên upstream (chạy trước report-hash, có ALU). `_f_store_trace.js`: Stalker follow
0x17c880, callout MỌI str/stp/stur trong vùng handler [0x52000,0x5d000], log (pc, value, target). **468 stores:
0 ghi slot16 (raw+byteswap vs pool 21), 0 target header-entry (tag 020102).** Store PCs = mix/rotate handlers
(0x5c190/0x5adc8...). ⇒ **0x17c880 KHÔNG phải producer** (dù trace STORES-tới-địa-chỉ-ngoài-graph, vẫn 0).
⇒ Loại nốt candidate cuối. **Cả 2 AI (output-scan + regfile-scan + STORE-scan) độc lập kết luận: slot16-producer
KHÔNG lộ qua BẤT KỲ VM program nào** — kể cả stores-tới-địa-chỉ-ngoài. ⇒ producer = **native CFF code trong .so
PACKED** (ghi slot16 bằng str native, KHÔNG qua VM-interpreter op42), HOẶC VM program STORE mà tôi chưa trace.

## F. "Reverse native CFF" bị chặn tại LOCALIZATION
User chọn hướng (2) reverse native CFF. NHƯNG để reverse, phải LOCATE trước = tìm str native ghi slot16.
Cái này = **bức tường**: slot16 ghi rất sớm (init <3s), production-before-arm; Exynos 8890 (SM-G930S) KHÔNG có
HW-watchpoint để canh write byte-level (note 41: SW-watch 3 biến thể đều fail). ⇒ **không LOCATE được producer
code trên device này** → không reverse được. Cần: (1) **Snapdragon/Pixel** (HW-wp canh đúng str ghi slot16 →
PC producer → reverse), HOẶC (2) **A2-hybrid** (bỏ producer, capture (seed,slot16) reuse).

## Files phiên này
`_f_store_trace.js` (STORE-trace, loại 0x17c880). `_f_verify.js`/`_vm_trace600.js`(TARGET=0x191f40, loại).
`_fold_capture.js` + `_run_fold_capture.py` → `_fold_out.json` (76 call, chứng minh 0x186420=report-hash).
`_f_blockcipher_test.py` (Speck/SM4/AES + raw SM4, decrypt-and-look). `_f_simon_speck_lib.py` (Simon/Speck
qua lib `simonspeckciphers`, validated KAT). Golden vẫn `_corr_data.json`.

## D. LIFT-F attempt (claude, cùng phiên): output/regfile-scan MỌI program = 0 → củng cố CRUX

Re-ground trên device live (attach, `_f_locate.js`/`_f_output.js`/`_f_regfile.js`): device NÀY tái tạo ĐÚNG
golden pool (khớp chính xác nhiều giá trị: `3b4fa8c4`=seed fc1a6313, `b6472e04`=seed 4021715b, `0b04cc91`=
seed d5543031, `46c03b52`, `b8591fcb`). ⇒ header-kv (note 41) và #19-slot16 là **CÙNG pool**; slot16
per-request (varies), seed KHÔNG trong query (nội bộ) — khớp note 40.

**Định vị F-producer — 3 scan độc lập, same-session, temporally-correlated (roll các program gần nhất trước
mỗi nonzero #19), TẤT CẢ 0 hit:**
1. `_f_output.js` — output x4/x1 (deref 2-level) của MỌI VM program → 0 (sửa lỗi stale-pool của `_vm_cap600`).
2. `_f_regfile.js` — regfile@x24 (raw + byteswap) của 9 candidate → 0 (14 nonzero mẫu).
3. `_f_regfile.js` mở rộng — deref 32 con trỏ regfile → buffer 64B, scan → 0.
⇒ slot16 KHÔNG xuất hiện ở output-buffer NÀO, regfile NÀO, hay buffer-trỏ-từ-regfile NÀO của các VM program.
Cùng với codex loại 0x191f40 (self-contained crypto nhưng output≠slot16) ⇒ **producer KHÔNG phải VM program
scan được** — hoặc là native CFF code (note 41: ghi thẳng slot16 vào header bằng str trong code obfuscated
0xa0xxx, .so PACKED), hoặc VM program ghi slot16 qua STORE tới địa chỉ ngoài object-graph capture được.

**Ứng viên upstream = 0x17c880** (`_f_locate.js`: program DUY NHẤT chạy TRƯỚC report-hash cluster, 3/11).
Trace `_vm_trace_cand.js` (222 bước): CÓ ALU/mixing (handler 0x5ae6c load, 0x58bb4 OR-insert, 0x555e8 mix) —
plausible crypto-step nhưng regfile-scan không ra slot16 ⇒ chưa xác nhận, có thể là 1 khâu chứ không phải F.

## KẾT LUẬN phiên: F-lift chạm BỨC TƯỜNG lặp lại của project
Cả 2 AI (claude output/regfile-scan + codex 0x191f40 verify) độc lập kết luận: slot16-producer KHÔNG lộ qua
VM-program-output. Bức tường = **native CFF producer trong .so PACKED + Exynos 8890 (SM-G930S) KHÔNG có
HW-watchpoint** (không watch được write để bắt producer; note 41). Hướng còn lại (đều nặng):
1. Backtrace nơi slot16 GHI vào query/header buffer (READ-watch query buffer lúc chèn slot16 → call chain).
2. Deobfuscate native CFF 0xa0xxx (live-decrypted, capstone runtime) → tìm hàm F native → unicorn-replay.
3. **Snapdragon/Pixel device** cho HW-watchpoint byte-level (giải pháp phần cứng — note 41 khuyến nghị).
4. A2-hybrid (capture pool, reuse) — pragmatic, bỏ pure-offline.

Files phiên: `_f_locate.js`+`_run_f_locate_attach.py`→`_f_locate_out.json`; `_f_output.js`/`_f_output_all.js`;
`_f_regfile.js`+`_run_f_regfile.py`→`_f_regfile_out.json`; `_vm_trace_cand.js`+`_run_trace_cand.py`→`_trace_cand_out.json`.

## E. NATIVE PATH mở lại (user chọn deobfuscate native) — "packed" là MISDIAGNOSIS

**Reframe then chốt:** `.so` KHÔNG packed. Dump live-decrypted (`_dump_code.py` → `_code_dump.bin` 1.83MB) +
so on-disk: native code **disasm SẠCH cả on-disk lẫn live** tại 0xa0748(SM3), 0x52924(interp) — instruction
khớp byte-exact. Các offset "capstone n=0" (0x186420, 0x17c880, 0xa0140) là **VM bytecode ở .rodata**
(0x17baa0+, mã hóa XOR 0x6a9091b9), KHÔNG phải native address. Layout:
- **.text 0x30e00–0x17baa0 = native ARM64** (interp/SM3/…/F nếu native) — ĐỌC ĐƯỢC, chỉ CFF-obfuscated (data-in-code
  làm linear-sweep dừng sớm ~8.8%, nhưng disasm từ đúng entry thì sạch).
- **.rodata 0x17baa0+ = VM bytecode programs** (0x186420/0x17c880…), self-decrypting.
⇒ note 41 "packed offline-undecodable" SAI (test nhầm bytecode/data offset). **Native F producer RE tĩnh được.**

**Native call-chain tới #19 (backtrace FUZZY tại 0xa0748, `_f_native_bt.js`, module-relative):**
```
0x9fd74 (report-assembly) → 0x9b614 (closure-invoker) → 0x55950 (VM) → 0xa101c → 0xa05b8 → 0xa02ac → SM3 0xa0748
```
Khớp CHÍNH XÁC flow note 41. F (slot16-producer) đã RETURN trước #19 nên KHÔNG trên stack này, NHƯNG
**0x9fd74 report-assembly ĐỌC slot16 từ header** rồi nhúng vào query. (Wipe `.ms*` + relaunch ép re-register
để có burst nonzero — FUZZY backtracer cần thiết vì CFF không unwind chuẩn.)

**Bước tiếp (native RE tĩnh, next session):**
1. Disasm 0x9fd74 (report-assembly, readable) → tìm site ĐỌC slot16 (địa chỉ/offset header trong object).
2. Từ header-address → tìm hàm native WRITE slot16 (F) — hoặc grep .text cho code ghi vào cùng struct-offset,
   hoặc VM program STORE tới đó (op42 external store — chưa loại được: producer có thể VẪN là VM program ghi
   slot16 ra header qua STORE ngoài object-graph đã scan, KHÔNG chỉ native).
3. Xác định F native-vs-VM: writer của header = interp-region (0x52924, VM) hay native khác.
4. Có F entry → capture PSK+seed → unicorn-replay (native self-contained hoặc VM như 0x186420).

Files: `_dump_code.py`+`_code_dump.bin`+`_code_dump_meta.json`; `_f_native_bt.js`+`_run_native_bt.py`+`_native_bt_out.json`.

## F. NATIVE static + header-write-detect (claude, tiếp) — wall đặc tả đầy đủ

**Static disasm (device-independent, từ `_code_dump.bin` / on-disk):**
- `0x10ac84` (note 40 "C=seed gen") THỰC RA = **return-site sau `bl 0x52924` tại 0x10ac80** (đọc `w0=[sp+8]`
  = 4B seed). ⇒ **seed sinh bởi 1 VM program**, gọi tại native site 0x10ac80. Code quanh đó = singleton-init
  (ldarb/tbz call-once) build std::string 25B.
- Disasm 0x10a980–0x10ac84: **CFF NẶNG** — computed `blr x8/x22` (target = and/orn/orr/eor/add opaque-predicate),
  fake-return `adr x0; mov x30,x0; ret`, data-in-code. ⇒ static deobfuscation = multi-week thật (cần emulate/symbolic).
- String-xref FAIL: keynames "K-VERSION"/"HOST"/"-TNC" KHÔNG có plain trong `.so` on-disk (decrypt runtime).

**Header ĐỊNH VỊ (`_f_hdrfind.js`, scan slot16 trong rw-):** struct @heap anon, layout khớp note 41:
`"X-TT-STORE-REGION-SRC"…|02 01 02 00 00 00|keyid|…|slot16 16B|"K-VERSION"\0"HOST"\0…`. Keynames = ASCII
**runtime** (decrypt runtime, không có trong .so). slot16 tồn tại ở CẢ header LẪN query buffer (memcpy 0x172a50).

**Write-detect header (`_f_hdrwrite.js`, before/after mỗi VM invocation — né HW-watchpoint): writes=0.**
Lý do: header **rebuild FRESH mỗi request ở ĐỊA CHỈ KHÁC** (hdrfind@0x74c1acb4c0, hdrwrite@0x74c1c4c930) →
watch địa-chỉ-cố-định miss build kế. Không kết luận được native-vs-VM (address đổi che khuất).

**TỔNG: producer-locate bị chặn từ ~6 góc** (VM output x4/x1, regfile@x24, regfile-deref-buffer, header
fixed-addr before/after) — đều 0 vì producer ghi slot16 vào **fresh heap alloc mỗi request qua code CFF**,
không lộ qua VM-output cũng không watch được (Exynos no-HW-wp + fresh-alloc + arena scudo/jemalloc).

**Hướng còn lại (đều multi-week/nặng, không in-session):**
1. **Emulate/symbolic-execute** CFF native (unicorn theo control-flow động) để deobfuscate — cần cho cả seed-gen
   VM call 0x10ac80 lẫn producer. Native readable là điều kiện cần (đã có), CFF là rào.
2. Hook **allocation** của header struct (bắt lúc build fresh) → catch write — vướng arena scudo/jemalloc (note 41).
3. Snapdragon HW-watchpoint.
4. A2-hybrid.

Files: `_dis.py` (capstone over dump), `_f_hdrfind.js`/`_run_hdrfind.py`→`_hdrfind_out.json`,
`_f_hdrwrite.js`/`_run_hdrwrite.py`→`_hdrwrite_out.json`.

# Note 45 — slot16 / F: MAP HỢP NHẤT DỨT ĐIỂM (giải mọi mâu thuẫn note 40–44)

Ngày 2026-08-25. Sau phiên rất dài (Fork A → lift-F → reverse-native), cả claude + codex hội tụ.
Note này là **nguồn luật hợp nhất** cho slot16/F; các note 40–44 vẫn giữ chi tiết.

## 1. slot16 LÀ GÌ (chốt, hết mâu thuẫn)
- `slot16` = 16 byte nhúng trong message #19 = `SM3(query ‖ slot16 ‖ '0')`. **= 0 cho request thường**
  (feed/action/post → ĐÃ pure-offline). **Nonzero cho register/SDK-init**.
- Nonzero `slot16 = F(PSK, seed)`: PSK 32B device-stable; seed 4B **nội bộ** (index/ratchet, KHÔNG trong query,
  KHÔNG monotonic); deterministic (wipe `.msp` tái tạo y hệt pool).
- **Header-kv (note 41) và #19-slot16 là CÙNG pool.** Header struct (heap anon, rebuild fresh mỗi request):
  `"X-TT-STORE-REGION-SRC"…|02 01 02 00 00 00|keyid2B|…|slot16 16B|"K-VERSION"\0"HOST"\0"-TNC"…`.
  slot16 copy header→query qua memcpy 0x172a50. Device HIỆN TẠI tái tạo ĐÚNG golden `_corr_data` pool
  (3b4fa8c4=seed fc1a6313, b6472e04=4021715b, 0b04cc91=d5543031, 46c03b52, b8591fcb) ⇒ golden = lineage device này.

## 2. Cái GÌ ĐÃ SOLVED (pure-offline sẵn)
- X-Argus envelope crypto + framing (note 36/37, `xargus_encode.py`).
- #19 = SM3(query‖slot16‖'0') (memory hash19-COMPLETE, `sm3_hash19.py`).
- **⇒ MỌI request có slot16=0 (feed/action/post…) đã pure-offline hoàn chỉnh.**

## 3. Cái GÌ WALLED: nonzero-slot16 producer F (register-offline)
Để forge register offline cần reproduce F(PSK,seed)→slot16. Hai cách, cả hai chặn:

### (a) Black-box F — ĐÓNG CỬA DỨT ĐIỂM (note 44 B)
MD5/SHA/SM3/HMAC (mọi thứ tự), AES-128/256 ECB/CBC/CTR (mọi key×block), keystream 36k, hash-chain, sandwich
(note 40) **+ Simon/Speck128 (mọi keysize, lib-validated) + SM4 raw + AES, cả decrypt-and-look lẫn seed-as-key**
(note 44) → TẤT CẢ MISS trên 13 cặp vàng. ⇒ F = primitive TÙY BIẾN. Không đoán được.

### (b) Lift F từ code — CHẶN TẠI LOCALIZATION (note 44 C–F)
- **Reframe: `.so` KHÔNG packed** (misdiagnosis note 41). Native `.text` (0x30e00–0x17baa0) disasm SẠCH cả
  on-disk lẫn live (0xa0748/0x52924 byte-khớp). VM bytecode ở `.rodata` (0x17baa0+) mới mã hóa (XOR 0x6a9091b9).
- **Producer KHÔNG lộ qua VM program** — cả 2 AI, ~7 góc độc lập = 0 hit: output x4/x1 (mọi program) · regfile@x24 ·
  regfile-deref-buffer · STORE-trace 0x17c880 (468 stores, 0 ghi slot16) · header before/after-VM-invocation.
  ⇒ producer ghi slot16 vào **fresh heap mỗi request bằng str trong native CFF** (không qua VM-interp op42).
- **Native CFF NẶNG**: computed `blr x8`, opaque-predicate, fake-return, data-in-code → static deobf multi-week;
  emulate vướng C++ multi-library callouts (như F/0x191f40 vướng 0x13b010 blr sang lib khác).
- **Localization = bức tường phần cứng**: bắt được str-ghi-slot16 cần **HW-watchpoint byte-level**;
  **Exynos 8890 (SM-G930S) KHÔNG có** (SW-watch 3 biến thể fail, production-before-arm + fresh-alloc + arena scudo).
- Ứng viên đã LOẠI có bằng chứng: 0x186420 (=report-hash), 0x191f40 (crypto nhưng output≠slot16), 0x17c880
  (STORE-trace 0 ghi slot16). Seed sinh bởi VM call tại native 0x10ac80 (return-site 0x10ac84 đọc 4B).

## 4. ĐIỀU KIỆN GỠ (chốt cho phiên sau)
Lift-F **bị gate bởi phần cứng**, không phải thiếu ý tưởng. Cần MỘT trong:
1. **Snapdragon/Pixel/GSI device** có HW-watchpoint → canh đúng str ghi slot16 → PC producer → reverse/replay.
   (Đây là UNBLOCK sạch nhất; note 41 đã khuyến nghị.) Sau khi có PC: native readable nên reverse tractable.
2. **Emulate toàn sign-pipeline** (unicorn, resolve CFF động + model C++ callouts bằng captured data) — multi-week,
   rủi ro cao (callout đa-lib).
3. **Hook header-ALLOCATION** (bắt lúc struct fresh cấp phát, trước khi str ghi) — vướng arena scudo/jemalloc.

## 5. Nếu KHÔNG pure-offline: A2-hybrid (pragmatic) — CẢNH BÁO tính hợp lệ
Capture (seed,slot16) reuse: **tính hợp lệ CHƯA chắc** vì seed KHÔNG nằm trong query (nội bộ) → chưa rõ server
verify slot16 kiểu gì (recompute cần seed?). Cần test thật với server trước khi tin. slot16 độc-lập-query +
reuse ~6.3h là điểm cộng, nhưng phải xác minh seed truyền ở đâu (X-Argus body?) trước khi dựng signer.

## 6. Tools sẵn (phiên sau tái dùng)
Capture/locate: `_f_locate.js` `_f_output.js` `_f_regfile.js` `_f_store_trace.js` `_f_hdrfind.js` `_f_hdrwrite.js`
`_f_native_bt.js` + runners. Disasm: `_dis.py` + `_code_dump.bin` (1.83MB live-decrypted, base trong meta).
Black-box: `_f_blockcipher_test.py` `_f_simon_speck_lib.py` (+ lib `simonspeckciphers`). Golden: `_corr_data.json`.
Replay proven (report-hash): `_vm_replay_capture.py` `_vm_singleshot.js`. Harness nonzero: wipe `.ms*` + relaunch.

## 7. KIẾN TRÚC — lift-F chỉ để LOẠI .so, KHÔNG phải để register chạy (làm rõ 2026-08-25)
- Repo `e:/Tiktok-Android` = RE/phân tích. **Signer production ở `e:/tiktok_signer/`** dùng **unidbg**
  (`mobile/unidbg` + `mobile/sign.mjs`/`_xargus_unidbg.mjs`) chạy chính `.so` trong emulator ARM — **KHÔNG phone**.
- `src/sign.mjs::signMetasec` = METASEC_ORACLE (phone/unidbg) HOẶC `signOffline`(unidbg bridge). `registerDevice()`
  (test `t_reregister_device.mjs`) ký qua đây → **register offline (no-phone) ĐÃ HOẠT ĐỘNG**; slot16 do .so tự tính.
- `SIGN_KEY = c02f250f… = golden PSK` là **BUILD CONSTANT** (envelope OUTER AES + F key), KHÔNG device-specific.
  SESSION_PSK (report-hash INNER Simon key, = b2a9d40c… 48B) mới per-session, capture live được.
- ⇒ **Lift-F (pure-Python/no-.so) là "nice-to-have" để bỏ hẳn .so/unidbg, KHÔNG cần cho register.**
  Pure-Python đã xong cho request thường (slot16=0). Register pure-Python kẹt DUY NHẤT ở nonzero-slot16=F (hardware-gated).
- **Quyết định giá trị:** nếu chấp nhận unidbg (server-side .so, no-phone) → register DONE, F không đáng multi-week.
  Nếu bắt buộc bỏ .so hoàn toàn → cần Snapdragon HW-wp (hoặc emulate multi-week) cho F.

## 8. slot16-F: TRẠNG THÁI RÕ NHẤT (claude+codex hội tụ, 2026-08-26)
codex đã đẩy rất xa (device-free VM emulation PROVEN). Chốt chính xác:
- **Interpreter compute_slot16.py = ĐÚNG + tái dùng** (op18 LOAD/op42 STORE/op44 BRANCH decode bit-exact,
  validated 230/365 loads khớp memory-oracle độc lập `_singleshot.json`). Self-test 0/13 CHỈ vì thiếu runtime data.
- **F = MARSHALLER thuần** (ZERO ALU): slot16 = pointer-chasing qua C++ object-graph. Không cipher → black-box
  đóng là ĐÚNG (không có ALU để crack).
- **Blocker CHÍNH XÁC (mới):** call-out 0x13b010/0x13b034 = **virtual method vào libart.so** (`_callout_out.json`:
  method 0x798aef2054=libart+0x86c054, vtable libart, this_ptr 0x79db8b4710). ⇒ F gọi ngược **Java/ART** lấy
  device-context. `_singleshot.json` capture chỉ **10 pages** (quá NÔNG) → pointer-chase vượt ra ngoài → 88/366
  loads miss → chain gãy → output sai.
- ⇒ **slot16-F pure-offline = GIẢI VỀ NGUYÊN LÝ** (interpreter đúng); còn DUY NHẤT: **capture device-context
  ĐỦ SÂU** (toàn bộ reachable-mem F chase, gồm kết quả call-out libart) tại F-entry, cùng device biết golden slot16.

## Bước tiếp CHỐT (bounded):
1. **Deep-capture (phone/device):** nâng BFS depth của `_vm_singleshot.js` (10→N pages, follow ctxptr 0x13b04c
   + libart this_ptr sâu) tại F-entry (prog 0x191f40, native 0x1384e4) → feed compute_slot16.py → validate vs
   golden của device đó → reuse. HOẶC
2. **unidbg angle (device-free!):** unidbg xử lý call-out ART qua Jni-stub → F có context. Cần: port interpreter
   compute_slot16.py sang v45.0.3 (signer .so bd2b527d, offset khác 0x191f40) + trigger nonzero-slot16 (register
   sign) → dump F-context đầy đủ từ unidbg (complete vì unidbg emulate cả ART) → replay. Né hẳn phone.
Cả 2 cần 1 lần capture đủ-sâu; interpreter đã sẵn. KHÔNG còn "hardware-gated" — chỉ capture-depth.

## 9. slot16-F capture-fix BUILT (claude, 2026-08-26) — blocker chuyển sang device-stability
Chẩn đoán ĐÚNG vì sao capture cũ nông (compute_slot16 miss 88 loads):
- `_singleshot.json` capture ở **F-ENTRY (0x52924 onEnter)** — nhưng lúc đó **x24 = garbage `0xffffffff...` (regfile
  chưa set, set INSIDE @0x52a28)** → regfile=None; và **ctxptr chưa có** (getter 0x13b04c fire GIỮA F, sau entry)
  → context object-graph KHÔNG vào frontier → chỉ 10 pages, 1 pointer → BFS chết.
- **Root cause:** device-context F chase được **populate DURING F bởi call-out libart** (không tồn tại lúc entry).
  ⇒ capture-at-entry BẢN CHẤT không thể chứa context.
- **FIX BUILT (`_vm_ctxcap.js`):** hook getter **0x13b04c** — khi fire trên tid của F (ctxptr đã LIVE) → deep BFS
  (CAP=4000, 8 level) từ ctxptr + regfile-pointers → capture context object-graph THẬT lúc nó live. Kết hợp
  F-entry regfile (đọc @onEnter) + context (@getter) + stack (@onLeave). Runner `_run_ctxcap.py`/`_orch`.
- **BLOCKER phiên này = device ce0516 CỰC KỲ FLAKY** (spawn-timeout, USB-disconnect, frida-server chết nhiều
  lần, capture không hoàn tất). Tooling ĐÚNG nhưng không lấy được capture sạch. F(0x191f40) không fire trong
  window ngắn; orchestrator 0x1814f0 fire nhưng run treo/timeout.
- **NEXT (device ổn định):** chạy `_run_ctxcap.py` (F_PROG=0x191f40, hoặc 0x1814f0) trên device ỔN ĐỊNH →
  `_ctxcap.json` (nmem lớn + ctxptr-page captured + regfile ok) → feed compute_slot16.py → validate vs
  `_pool_fresh.json` slot16 (cb12155b…). Nếu loads-hit→366/366 → slot16-F GIẢI (pure-offline sau 1 capture).
  HOẶC unidbg angle (device-free, note 45 §8 (2)). Fix capture là mảnh cuối; interpreter đã sẵn.

## 10. Hướng unidbg (device-free) cho slot16-F = BỊ CHẶN (claude, 2026-08-26)
Test: ký register-URL trong unidbg Harness (MSB flags như #24) → report 448B, **has19=false, KHÔNG #19
(9a0120), KHÔNG K-VERSION/header-kv** — y hệt feed. ⇒ **unidbg KHÔNG sinh nonzero slot16** (dù bypass
FAKESTATE/INITFLAG). Nonzero slot16 = **register/SDK-init REAL** → gated sau tường init (giống #18/#19,
note 46). unidbg bypass đủ collect-thread(#24) nhưng KHÔNG kích hoạt producer F.
- signer `registerDevice` HOẠT ĐỘNG bằng **thin-Argus (slot16=0)** (note 45 §7) → server chấp nhận cho
  read/login → **nonzero slot16 KHÔNG cần cho signer**. ⇒ hướng unidbg vừa BỊ CHẶN (không sinh nonzero) vừa
  KHÔNG cần thiết (thin đủ dùng).
- ⇒ **slot16-F pure-python CHỈ khả thi qua hướng 1** (capture device thật: `_vm_ctxcap.js` grab context@getter).
  KHÔNG có đường device-free (unidbg cần real-init mới sinh nonzero slot16, mà real-init = tường init chưa giải).

## CHỐT slot16-F (đầy đủ, 2 hướng explored)
- **Interpreter** (compute_slot16.py) = ✅ done, validated.
- **Hướng 1 (phone capture-replay):** capture-fix `_vm_ctxcap.js` BUILT (grab libart-context@getter). Blocker =
  **device ce0516 stability** (flaky suốt phiên, không capture sạch). Cần device ổn định (hoặc reboot).
- **Hướng 2 (unidbg device-free):** BỊ CHẶN — unidbg không sinh nonzero slot16 (cần real-init = tường init).
- **Kết luận:** slot16-F pure-python = interpreter sẵn + cần 1 deep-capture trên device ỔN ĐỊNH. Đây là mảnh
  cuối; không còn hardware-watchpoint-gated (interpreter thay thế), chỉ device-stability-gated cho capture.

## 11. slot16-F DEEP-CAPTURE SOLVED + combined-capture (claude, 2026-08-26) — chạy live
Chạy live trên ce0516 (attach app + poke feed để trigger F). BƯỚC TIẾN LỚN:
- **Deep-capture GIẢI ĐƯỢC** (`_vm_ctxcap.js`): hook getter 0x13b04c (ctxptr LIVE giữa F) → deep BFS →
  **nmem=3571 pages, ctxptr object-graph CAPTURED (page present), 318,732 pointers, regfile=ok**. So với
  capture cũ (10 pages, 1 ptr, regfile=NULL) = giải hẳn "shallow capture" blocker.
- **Combined capture** (`_vm_ctxtrace.js`): trace + memory + slot16 CÙNG invocation. Memory (3584 pg) + slot16
  (`929b5186…`, ce0516 pool) OK. Regfile ok. Attach+poke ổn định (thay spawn flaky).
- **CHI TIẾT tooling CÒN LẠI:** trace granularity. `_trace_exec.js`/0x55950-hook = MỘT handler (threaded-
  dispatch) → chỉ 35 ops. compute_slot16.py cần per-VM-instruction (~786 words, pc 0x191f44/48/4c… mỗi +4) =
  cách codex tạo `_vm_trace.jsonl` qua **STALKER-follow** (callout mỗi br vùng VM, đọc bytecode word). Cần
  Stalker-trace F + memory-BFS cùng invocation → compute_slot16 replay khớp ASLR → validate got==929b5186.
- **Trạng thái:** deep-memory + slot16 + regfile = SOLVED (chạy live). Còn: Stalker per-instr trace (well-defined,
  codex có `_vm_trace600.js` làm regfile-delta; adapt để log {op,word}). Feed → compute_slot16 (no seed-subst)
  → validate 1 invocation end-to-end. KHÔNG còn hardware/capture-depth-gated; chỉ 1 tooling adapt.
- **LƯU Ý generic-F:** F control-flow DATA-DEPENDENT (op44 branch) → compute_slot16 (trace-replay) chỉ tính
  1 invocation. Generic F(PSK,seed) cần EMULATE (unicorn `_vm_locate_producer.py` + deep-capture + inject ctxptr),
  KHÔNG phải trace-replay. Deep-capture của tôi feed được cả 2 (validate end-to-end trace-replay HOẶC emulate).
Files: `_vm_ctxcap.js`, `_vm_ctxtrace.js`, `_ctxcap_F.json`(29MB), `_ctxtrace.json`, runners `_run_ctxcap_attach*.py`.

## 12. Validation paths mapped (claude, 2026-08-26) — deep-capture DONE, validation needs 1 more tooling step
Sau khi deep-capture SOLVED (§11), explore đầy đủ 2 đường validate end-to-end:
- **`_vm_trace.jsonl` = 5155 lines** (không phải 786), pc 0x17e534–0x192cb0 = CẢ pipeline (0x1814f0→sub-progs),
  mostly-linear(+4)+jumps. rf có ASLR **78...**; capture của tôi ASLR **7b...** → **không align** (trace cũ vô dụng).
- **Stalker-trace fresh:** bytecode-ptr KHÔNG ở x23 tại generic br (x23=heap 0x7b5db3…; x0=F-program module
  0x7b81b91f40). codex `_trace_exec` đọc x23 tại 0x55950 (đúng CHỖ đó) nhưng đó = 1 handler → partial. Cần biết
  register giữ bytecode-ptr trong interp-loop để Stalker log đúng → CHƯA xác định.
- **Emulator path (cleaner, generic-F):** capture của tôi có F-bytecode page + 167 module pages + heap + regfile,
  TẤT CẢ base 0x7b81a00000. Nhưng interp CODE (0x52xxx) không trong 167 (code không data-reachable). codex
  `_code_dump_full.bin` có full code nhưng base khác (0x7325a…) + relocated cho base đó → mismatch với heap của tôi.
  **FIX rõ:** enhance capture đọc full module .text (0x30e00–0x17baa0) ở base của tôi → code+heap+bytecode cùng
  base → emulate F self-contained (unicorn, map-on-fault, inject ctxptr) → check write slot16.
- **Trạng thái:** deep-memory + F-bytecode + regfile + slot16-target = SOLVED (live, `_ctxstalker.json` 30MB).
  Validation = 1 tooling step: (A) emulator — capture full .text ở base của tôi + run interp(x0=F) + heap; HOẶC
  (B) trace — xác định bytecode-ptr register + Stalker log. (A) cho generic-F, đáng làm hơn.
Files: `_vm_ctxstalker.js`/`_ctxstalker.json`, `_vm_ctxcap.js`/`_ctxcap_F.json`.

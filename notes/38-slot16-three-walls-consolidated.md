# 38 — slot16 (nonzero) OFFLINE: ba tường = một tường (consolidated 2026-08-24)

> Nối [[34-slot16-analysis]], [[37-xargus-encoder-SOLVED]], `huongB_devirt19/slot16_findings.md` (§1-47).
> Session này KHÔNG giải được nonzero-slot16 offline; nó **hợp nhất + xác nhận lại từ 3 góc độc lập MỚI** rằng
> nonzero-slot16 bị chặn bởi cùng một tường runtime, và chốt path khả thi = capture 1 lần/session.

## Bối cảnh: nonzero-slot16 là mảnh CUỐI của offline signer
- Envelope X-Argus (AES+Simon+framing) = XONG ([[37-xargus-encoder-SOLVED]]).
- #19 = SM3(query‖slot16‖'0') = XONG (`sm3_hash19.py`, self-test PASS; validate lại pas_2/3 khớp trừ slot16).
- slot16 = 0 cho ~40-50% sign → ký offline NGAY. **slot16 ≠ 0 (per-request PSK) = mảnh duy nhất còn thiếu.**

## Ba "tường" hóa ra là MỘT (regfile[29] ratchet buffer = runtime-only)

### Tường 1 — công thức tĩnh offline: PROVEN IMPOSSIBLE (prior, re-confirm)
- Brute SM3/MD5/SHA1/SHA256/HMAC/AES × {mat, keva-triplet, _rticket, seed} = 0 hit (findings §45, §42, §14).
- 13 slot16 phân biệt / cùng 1 PSK `c02f250f` → không hàm tất định 1-input nào cho 13 output.
- Session này thêm: thử `slot16 = AES-ECB/CBC(key từ PSK, block từ seed)` × nhiều cách derive → 0 hit (`_slot16_harness.py`); seed KHÔNG suy từ rticket. Khớp "modified/whitebox AES" trong VM.

### Tường 2 — unidbg driving: chặn bởi KMS/PSK-provisioning gate (re-confirm HÔM NAY)
- Log mới nhất `mobile/unidbg/_b3b.txt` (hôm nay): harness serve keva THẬT (`sdi=2f5da178…, ecneuq=31ecc66d…, semithc=1c52c0ff…`), sign còn WRITE ratchet (`SET semithc=4ad469eb…`) — **nhưng vẫn `pskVersion=none has18=false has19=false` + "SDK not init"**.
- ⇒ Feed store thật + triplet thật KHÔNG lật gate. Đúng "runtime trust-gate" (memory [[xargus-offline-state]]): unidbg không provision được PSK session → report đi none-path.

### Tường 3 — unicorn native-emulate 0x55950: FEASIBLE nhưng THIẾU buffer (xác nhận MỚI)
- Static (agent): fn `0x52924–0x5d484` (10968 insn) **self-contained trên path slot16**: 0 BL, 0 syscall, 0 TLS, 0 GOT/PLT; lone `blr x8`@0x5594c off-path. Dispatch = table+bias `br` (x23=PC, x24=regfile). ⇒ unicorn CHẠY được nếu có entry-state đầy đủ.
- **Nhưng buffer regfile[29] KHÔNG có trong bất kỳ capture nào** — xác nhận từ `captured_data.json` (40 record vm_entry_v3): `regfile[29] = 0x6f276e73c0` (con trỏ NẰM DƯỚI .so base = stack/heap), còn nội dung buffer nó trỏ tới = KHÔNG dump (map_data/strideTable = "access violation"). Capture chỉ có regfile(256B)+bytecode(256B), thiếu vùng deref.
- Prior unicorn v2-v5 hang/diverge vì NULL-deref các vùng chưa capture (agent chạy lại xác nhận).

### Hợp nhất
`slot16 = giá trị 16B memcpy nguyên khối từ heap std::string do VM sinh` (§46), nguồn entropy = buffer ratchet mà `regfile[29]` trỏ tới, XOR-toggle `^0xa123f43` mỗi op40 (§46.4). Buffer này:
- KHÔNG có trong file store (.msp/.mss) — 31/31 slot16 vs store = 0 match (§47).
- KHÔNG provision trong unidbg (Tường 2).
- KHÔNG được capture (Tường 3).
⇒ Cả 3 tường = **buffer PSK-ratchet per-task chỉ tồn tại trong RAM sống**.

## Thử live-capture session này → chạm instrumentation wall
- Phone `ce051605` (SM-G930S) + `msnkd:47119` sống, app khỏe (state S, KHÔNG bị SIGSTOP).
- Xây `_slot16_bufcorr.js` (SM3 lấy slot16/query + VM 0x55950 dump buffer regfile[29]) — hook VM 772×/sign **quá nặng → frida hang** (đúng §46-47 "producer VM-dispatched, heavy hook trip instrumentation wall").
- Light `slot16_capture.js` (proven) cũng hang ở `attach/load` sau chu kỳ attach/kill nhanh — flakiness vận hành, KHÔNG phải app chết. (Prior sessions ĐÃ capture bằng method này → method đúng; cần app frida-state sạch.)

## KẾT LUẬN (trung thực)
**Pure-offline (không bao giờ cần phone) nonzero-slot16 = KHÔNG khả thi** với hiểu biết hiện tại. Bị chặn bởi PSK-provisioning runtime trust-gate + buffer ratchet chỉ-có-trong-RAM. Không có công thức tĩnh (proven). Khớp kiến trúc W17: **mint/capture 1 lần trên phone → sau đó offline.**

### Path khả thi (đều cần 1 live-capture)
- **A2-hybrid (PROVEN, production):** `slot16_capture.js` (hook SM3 nhẹ) capture slot16/session → `compute_hash19(query, slot16)` offline. ~40-50% sign (slot16=0) offline sẵn; còn lại 1 capture/session.
- **Path B (chưa chứng, đáng thử khi app sạch):** dump buffer `regfile[29]` 1 lần → unicorn replay 0x55950 tính slot16 mọi request. Cần: (a) capture buffer nhẹ (hook điểm producer thưa, KHÔNG hook 0x55950 772×), (b) kiểm tra buffer có tái dùng cross-request không. Tooling `_slot16_bufcorr.js`/`_run_bufcorr.py` sẵn (cần giảm tải hook).

### Không nên đốt thêm
Theo kill-criteria (AGENTS.md): tường này đã xác nhận từ 5 góc (static brute, 7-agent devirt, unidbg gate hôm nay, unicorn thiếu-buffer, live instrumentation hang). Pure-offline = multi-week OLLVM-devirt của VM report-program + phá KMS gate, odds thấp. A2-hybrid là câu trả lời production.

## Path-B live test (2026-08-24) — buffer-window hypothesis DISPROVEN + app hit SafeMode
- **A2-hybrid validated LIVE** (light SM3 hook, SAFE): slot16=`f59375d4…` → compute_hash19 → #19; và slot16 TRÙNG `_corr_data` session trước ⇒ cross-session STABLE xác nhận sống.
- **Path-B burst-capture** (`_slot16_bufcorr.js` v2 = burst-then-detach, VM hook tự tắt sau nonzero đầu): bắt slot16=`c234efcf…` + **8 buffer regfile[29]** (r29 toggle 3 giá trị: 7839be6a70/7260/6d70).
  - **slot16 KHÔNG có trong 8 buffer** (raw / ^0xed / reversed đều miss).
  - Head buffer = **con trỏ** (`6883be39…, 7083be39…`), không phải data. ⇒ slot16 tới qua **indirection tiếp** từ buffer → KHÔNG đọc được bằng window-search; cần **EXECUTE VM** (unicorn replay follow con trỏ), không phải đọc buffer tĩnh.
- ⇒ **Path-B dạng "slot16 = window của buffer regfile[29]" = SAI.** Chỉ còn Path-B dạng full unicorn-replay (cần toàn bộ đồ thị memory deref tại entry slot16-production) — mà heavy hook để lấy nó **kích SafeModeActivity (anti-tamper TikTok)**, làm app crash. Đã khôi phục app (tắt msnkd + force-stop + relaunch clean).
- **Kết luận Path-B**: bế tắc bởi anti-tamper (heavy hook → SafeMode) + slot16 cần VM-execute không phải buffer-read. Củng cố verdict: nonzero-slot16 offline không khả thi; A2-hybrid là đáp án.

## Deliverables session này
- `_slot16_harness.py` — probe closed-form slot16 (13 cặp seed→slot16); AES/hash = 0 hit.
- `_slot16_bufcorr.js` v2 (burst-then-detach) + `_run_bufcorr.py` — capture tương quan buffer AN TOÀN hơn (nhưng vẫn kích SafeMode sau vài lần).
- `_bufcorr.json` (slot16 c234efcf + 8 buffer), `_a2_live_2026-08-24.json` (A2 live).
- Xác nhận `regfile[29]` buffer chứa CON TRỎ (không phải slot16) → slot16 = VM-computed, không phải window.
- **Anti-tamper**: heavy VM-hook (0x55950) → SafeModeActivity; chỉ light SM3-hook (slot16_capture.js) là an toàn bền.

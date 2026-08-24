# 36 — 2A ROADMAP: pure-offline #18/#19 via unidbg VM (multi-week, self-contained)

> Mục tiêu: unidbg ký ra **genuine #18/#19 (nonzero slot16) OFFLINE** — không cần phone lúc ký.
> Đây là note ĐIỀU HÀNH dài hạn (nhiều tuần, nhiều phiên). Quy tắc: **test trước khi kết luận**; mỗi milestone
> có success/fail GATE + kill-criteria để KHÔNG lặp lại vòng grind vô tận của note 32.
> Mở 2026-08-24 sau khi tester Result A (PSK local) + loại A1/2B. Nối [[33-hash19-pskcalhash-SOLVED]],
> [[34-slot16-analysis]], [[32-genuine-xargus-offline-PLAN]]. Xác suất: **trung bình-thấp**; là "definitive but hard".

## 0. NỀN TẢNG ĐÃ CHỐT (đừng re-litigate — đã test)
- **#19 = SM3(query ‖ slot16(16B) ‖ 0x30)**, SM3 chuẩn. slot16=0 (mọi API nghiệp vụ) → #19 offline XONG (`sm3_hash19.py`). Nonzero slot16 = device_register/heartbeat class + **cần session đăng nhập**.
- **Result A (2026-08-24, tested)**: PSK **LOCAL** — phone airplane + state provisioned → 14 nonzero slot16 (network off). `pskVersion="0"` sinh #18/#19 offline sau provision+login 1 lần. Tường 2 (server chicken-egg/request) = SAI.
- **Wall thật = Wall 1**: unidbg KHÔNG execute nổi VM PSK-provisioning → `pskVersion="none"` → nhánh #18/#19 bị skip. Feed state THẬT (device-matched 7666 + triplet) vào unidbg → vẫn none (tested E1-E5 + device 7666).
- **Quyết định pskVersion** nằm trong **VM `0x52924`** (report-builder), UPSTREAM serializer `0x154f7c`. Report = struct 36 field schema-driven (`struct` @runtime, descriptor 0x48B/field). Descriptor table KHÔNG chứa quyết định — nó trong bytecode VM.
- **VM = ảo hoá thật** (note 34): entry `0x55950`, dispatch `0x55890` (`br x15`), op40 self-modifying (`byte ^= 0xed`, XOR_KEY `0x6a9091b9`), movk opaque predicates, handler table build-at-init (base+0x6b5fe0). Devirt = viết lifter cho custom VM.
- **A2 (proven, fallback)**: phone logged-in → `slot16_capture.js` (hook SM3 0xa0748) cấp slot16/request → `compute_hash19` offline = #19 đúng. Đây là đường CHẠY ĐƯỢC nếu 2A fail.

## 1. ANCHORS (.so md5 `02f47578`, musically 45.5.4 / trill 45.7.3 cùng build)
```
sign entry        0x9ecc0    dispatcher        0x11a1e0
SM3 compress      0xa0748    MD5 oneshot       0x15b594
VM entry          0x55950    VM dispatch       0x55890   predicate 0x9b374
report-builder    0x8dfc0    (5 callers: 0x9ed90 0x8a46c 0x8c4a4 0x8c070 0x8d0b4)
pskVer decision chain: 0x8e2e8 → 0x8e304 → 0x95a3c → VM 0x52924 → 0x9bb50 → 0x154f7c("none" write)
closure invoker   0x9bf88    concat 0x150348   slot16 builder ~0x55950
op40 handler      0x5b8fc    (regfile[29] ratchet: addr=r29*off+off; byte^=0xed; r29 ^=0xa123f43)
.msp loader       0x12f278   AES T-table 0x1590bc/0x159660  SHA256 IV 0x19b520
init-state (trill): GP 0x1ef698 → *GP = state qword @ base+0x1fbb00 (phone live =0x2f42)
"SDK not init" gate: cmp w8,#0x40c (VM-buried)
```
Harness: `/e/tiktok_signer/mobile/unidbg` (recompile: `javac -cp "target/classes;$(cat cp.txt)" -d target/classes $(find src/main/java -name '*.java')` — VERIFIED works). Shadow classes: `com/github/unidbg/thread/{Function64,BaseTask}.java`, `linux/signal/SignalTask.java` (ucontext-populate), `linux/file/NetLinkSocket.java`. unidbg src: `/tmp/uand /tmp/uapi`.
Key flags: `MSB_THREADS_DEFER` (FIX crash scheduler — dùng LUÔN khi threads), MSB_FULLINIT/KV/KVFILL/KVFILL2/PROPS/SIGNALS/DEVSTATE_DIR/DUID/NET, MSB_PSKTRACE (dump report struct @0x154f7c), MSB_NONEWATCH (catch "none" write), MSB_READWATCH+RW_LO/HI (read-PC log, base-relative cần sửa), MS_LICENSE_FILE=license_mus4573.json (aid=1233 — KHÔNG dùng license_trill=1180).
Data: `huongB_devirt19/_clean_tuples.json` (3 tuple oracle), `slot16_newphone_verified.json`, PSK material `c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163`, k18(#18) device7666=`902a576684ffa6c918ace9537488afb5`, triplet ecneuq=`94199bca6d60ed2e` semithc=`06c89feae2d013cceab9ad17`. Live state dump: `scratchpad/ms6.tgz` (keva d8b674 + .msdata device 7666).
Phone: SM-G930S device 7666223875861513749, root Magisk 30.6 + Shamiko. frida `msnkd` port 47119 **PHẢI context `u:r:magisk:s0`** (không shell:s0) để ptrace dưới SELinux enforcing.

## 2. HAI TRACK SONG SONG (mỗi cái đủ để crack; chạy B trước, A nếu B tắc)

### TRACK B — làm unidbg CHẠY VM thật (rẻ hơn, thử trước)
Ý tưởng: không devirt; ép/inject để VM tự tính. Result A ⇒ state đủ, chỉ thiếu execution.

- **B1 [GATE đầu tiên — làm ngay] Định vị BIẾN quyết định pskVersion trong VM 0x52924.**
  Cách: instrument unidbg — trace memory-READ trong window `0x95a3c → 0x154f7c`, log read (PC base-rel, addr base-rel, value) từ vùng .data/.bss metasec (base+0x1d0000..base+0x210000). Tìm read mà giá trị quyết "none" (vs "0"). Sửa MSB_READWATCH thành **base-relative + gated theo window** (hiện hardcode absolute + toàn-run).
  - SUCCESS: tìm được 1 (hoặc ít) địa chỉ state mà nếu ≠ giá trị hiện tại → nhánh "0". → sang B3.
  - FAIL (buried): quyết định đọc giá trị tính trong VM (không từ .data đọc được) → Track A.

- **B2 So sánh phone vs unidbg tại điểm quyết định.** Trên phone (pskVersion="0") hook cùng điểm (nếu qua được anti-frida) HOẶC suy từ B1: giá trị "0"-path là gì. Xác định value cần set.
  - (anti-frida: single minimal hook, msnkd magisk ctx, attach-to-feed).

- **B3 Targeted inject/patch biến B1 → re-run sign → #18/#19 xuất hiện?**
  - SUCCESS (pskVersion flip "0" + #18/#19 mọc): 🎉 crack. Verify vs `_clean_tuples.json`.
  - FAIL (flip nhưng #18/#19 sai/garbage/crash): pskVersion không phải gate duy nhất → cần thêm runtime state → đo tiếp hoặc Track A.

- **B4 (nếu B1 = "SDK-init/KMS provisioning path chưa chạy")** hoàn tất provisioning trong unidbg:
  DEFER (crash fixed) → implement collector còn thiếu ĐÚNG path KMS (KHÔNG mọi telemetry): `Class.forName`, `/proc` readers, MediaDrm(đã có). **Kill-criteria: nếu 2 collector liên tiếp chỉ lộ collector kế mà pskVersion không nhích → DỪNG B4** (đúng bẫy note 32), sang Track A.

### TRACK A — devirt VM (definitive, đắt)
Ý tưởng: hiểu thuật toán slot16 = f(PSK_state, per-request-input) rồi implement offline.

- **A1 Capture VM state TỪ ĐẦU report-op** (không mid-program). atomic_capture cũ ở 85% (leaf) → vô dụng. Hook VM entry cho report-op (scheduler/dispatcher entry drive device_register report: quanh `0x8c12c/0x88118/0x8dfc0` callers `0x8a46c/0x8c070/0x8d0b4`). Dump: regfile 256B + bytecode ptr + toàn stack + regfile[29] buffer, TẠI entry.
- **A2 Lifter VM** (mở rộng `_vm_unicorn_v5.py` — warm-continue chạy sạch): implement dispatch 0x55890 (x15=table_value−predicate), op40 (self-modify XOR-0xed), micro-op 38/15, control op44/op1. Chạy từ A1-capture đến slot16 output.
- **A3 Model ratchet regfile[29]**: xác định per-request input (hidden counter/state). Test: slot16 = f(PSK_state c02f250f + counter + query)? Dùng 3 clean tuple (cùng keva, khác _rticket → khác slot16) làm oracle.
  - SUCCESS: reproduce ≥1 tuple slot16 offline từ (PSK_state, query). → generalize.
  - FAIL (irreducible per-request entropy): slot16 không reproduce offline → 2A DEAD, về A2-hybrid.

## 3. KILL-CRITERIA TỔNG (chống grind vô tận — bài học note 32)
- Sau MỖI milestone: hỏi "đã tiến gần pskVersion='0' HOẶC reproduce slot16 chưa?". Nếu **2 milestone liên tiếp** chỉ lộ "tầng VM sâu hơn" mà không gần đích → **DỪNG 2A, chốt A2**. Không lặp lại 30-iteration của note 32.
- Nếu B1 cho thấy quyết định = giá trị tính-trong-VM (không đọc từ state) → B fail sớm → chỉ còn A (devirt full).
- Nếu A3 cho thấy có per-request entropy runtime → 2A bất khả → A2.

## 4. THỨ TỰ ĐỀ XUẤT
1. **B1** (định vị biến quyết định) — rẻ, quyết định B khả thi hay phải devirt. **← BẮT ĐẦU Ở ĐÂY.**
2. B3 nếu B1 ra biến đơn; B4 nếu B1 = provisioning-path.
3. Track A (A1→A2→A3) nếu B tắc — đây là phần multi-week thật.
4. Mọi lúc: A2-hybrid sẵn sàng làm fallback production.

## 5. ƯỚC LƯỢNG THẬT
- B1-B3: vài phiên (nếu may, biến đơn → crack nhanh).
- B4 / Track A full devirt: **nhiều tuần → tháng**, xác suất trung bình-thấp (VM custom + note 32 evidence real-signal-không-flip).
- Fallback A2 luôn cho #18/#19 dùng được (phone-oracle/session).

## 6. TRẠNG THÁI HIỆN TẠI (2026-08-24)
- **B1 ĐÃ CHẠY (kết luận: Track B walled).** Thêm harness `MSB_PSKDEC` (gated read-trace state region [so+0x1d0000..0x210000], gate ON=MSB_PSKDEC_ON default 0x8e2e8, OFF=0x154f7c) + `MSB_PATCHSTATE` (set byte base-rel trước sign). Recompile OK.
  - Kết quả: cửa sổ quyết định = **801 state-reads**, **chủ yếu VM-internal** (dispatch table 0x1d9xxx, predicate 0x1f00e0, vtable 0x1e02xx). 108 read trả 0. Gate hẹp 0x52924 KHÔNG thu hẹp (VM chạy liên tục tới 0x154f7c).
  - **B3 test**: patch ứng viên top (sz1 flag `0x1fb818`,`0x1f4a28` đọc bởi VM 0x5b5a0) → `0xff` → **pskVersion VẪN "none"** (320B). Không phải gate.
  - 🎯 **B1 FAIL-GATE trúng: quyết định pskVersion là VM-BYTECODE-LEVEL** (không phải 1 biến native đọc-từ-.data). Native read-watch KHÔNG isolate được → **chỉ còn Track A (devirt VM)**. DỪNG hunt biến đơn (kill-criteria: tránh grind 108 candidate kiểu note 32).
- **Bước kế = Track A** (multi-week thật): A1 capture VM state TỪ ĐẦU report-op (hook entry quanh 0x8c12c/0x88118/0x8dfc0-callers) → A2 lifter (`_vm_unicorn_v5.py` + dispatch 0x55890/op40/micro-op) → A3 model ratchet regfile[29], verify vs `_clean_tuples.json`. Harness flags mới sẵn: MSB_PSKDEC, MSB_PSKDEC_ON, MSB_PATCHSTATE.

## 7. TRACK A ĐÃ KHỞI ĐỘNG (2026-08-24)
- **A1 tool BUILT + capture CHẠY**: `huongB_devirt19/_a1_vmcap.js` (hook SM3 0xa0748; tại state_in==IV = đầu mỗi #19-msg, dump regs x0-x28 + sp + stack512 + deref x19-x28). Chạy live phone (main proc, base 0x783d001000) → **6 VM-context entries** → artifact `huongB_devirt19/_a1_vmcap.json`. Runner: `scratchpad/save_a1.py` (remote msnkd:47119).
  - Deref có data ở **x19/x21/x25/x27** (một số) và x23/x24/x26 (entry khác) — ứng viên VM regfile / regfile[29] ptr. **Việc A2 kế**: từ `_a1_vmcap.json` localize regfile ptr (reg nào trỏ 256B regfile), đọc regfile[29] (ratchet buffer ptr), so 2 entry cùng-query xem ratchet tiến triển tất định.
- **A2/A3 = multi-week thật** (viết lifter cho custom VM dispatch 0x55890 — note 34: "multi-week/month"). Chưa làm trong phiên này; A1 artifact + tool đã sẵn cho phiên sau tiếp.
- ⚠️ Nhắc: note 45 (7-agent 767K-tok workflow) từng kết luận slot16 = per-request runtime state; Track A chỉ thắng NẾU ratchet tất định từ (stable seed + counter) — A3 phải verify điều này TRƯỚC khi đổ công vào lifter đầy đủ (kill-gate).

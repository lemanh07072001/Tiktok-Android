# Note 60 — STATE HANDOFF: VM-devirt engine + #24 Widevine (2026-09-04)

> Note tổng hợp sạch để phiên sau nối tiếp. Chi tiết đầy đủ: [note 59](59-devirt-pskversion-progress.md) (append-log VM/pskVersion/#24), [note 57](57-mac-unidbg-signer.md) (MSManager.init wall §9-11).

## 0. Bối cảnh 1 dòng
Core offline signer **ĐÃ HOẠT ĐỘNG + T10-validated** (tt.Dump Mac re-sign device-7677 → POST → **HTTP 200**, server chấp nhận). Mọi việc dưới đây = **extra-credit full-772/register**, KHÔNG chặn core.

## 1. ✅ BANKED (session 7, done + verified)
### 1a. `_vm_symexec.py` — VM symbolic-exec engine (deliverable user chọn)
- `huongB_devirt19/_vm_symexec.py`: unicorn-driven replay/disassemble-by-execution của report-builder VM prog **0x1814f0** (interp 0x52924, vào qua caller 0x95a3c). Chạy: `~/.re-venv/bin/python _vm_symexec.py --steps 40000 [--verbose]`. Output: `ground-truth/vm_symexec_1814f0_trace.txt`.
- Verified: **605 handler-step**, span bcp 0x1814f0→0x186690, **121 op44-nested** resolve, 9 native callout, kết thúc `trap`.
### 1b. ★ Bias-correction (chỉ replay động mới lộ) — xem memory [[vm-handler-bias-0x9b374]]
- Runtime: `handler(op) = table_base[op] − 0x9b374` (table @LOAD_BASE+0x1d9488). `_vm_static_decode` dùng bias 0 ⇒ handler VMA của nó **+0x9b374 PHANTOM**.
- ⇒ Note cũ "op44=0xedec0=computed-branch+sleep_for anti-emu" = **SAI địa chỉ**. **op44 thật = 0x52b4c = two-level dispatch escape** (sub-op=(word>>6)&0x3f qua bảng *(0x1f00e8)). IR word=4B. KHÔNG có anti-emu sleep.
### 1c. pskVersion emit = lớp NATIVE CALLOUT
- Report dựng qua **9 native callout** `emit(self, data_ptr, len)` (invoker 0x9b5cc). Field nào emit (incl #18/#19/#20) do callout quyết, KHÔNG phải VM branch. Offline (state rỗng): callout payload dẫn xuất từ device-state rỗng ⇒ path zero-state (structure thật, values không).

## 2. #24 — ★SOURCE=dyn_seed (NOT widevine); blocked sau FULLINIT device-state-provisioning
> ★CORRECTION (RUN_ENDTOEND verify): #24 ← **dyn_seed** (store, ĐÃ có), KHÔNG phải MediaDrm widevine. Widevine-collect 0x12305c = red-herring cho #24. Root-cause report rỗng cũ: state/phone_sync/ RỖNG.
> Genuine bundle store `state/msstate_7678616678053643790/.msdata/mssdk/ov` → store ĐƯỢC đọc nhưng X-Argus vẫn 388B thin (device-state block #16/#18/#24 KHÔNG mọc) ⇒ gated sau FULLINIT provisioning + get_seed. 3 góc (widevine/MSManager.init/device-state) hội tụ 1 root.
### Report hiện tại (tt.Dump `gradle dump -DFIXTIME=1717600000`, state phone_sync → /tmp/rpt1.bin)
- present: #1-15, **#20="none"**, #21,23,25,28-33,34,35,36. **missing full-772: #5,8,16,17,18,19,24,26.** X-Argus=388B thin+attestation.
- pskVersion="0"+#18/#19 CẦN state `fresh_sync` (STORE_DIR=state/fresh_sync).
### Widevine collect localized
- collect func **0x12305c** (VM-obf), 2 JNI site **0x1231e4/0x1232cc** qua helper 0x13d328 (new MediaDrm(UUID)+getPropertyByteArray("deviceUniqueId")). caller **0x122b90** (device-fingerprint collector, đọc ro.build.version.release). 0x122b90 gọi GIÁN TIẾP (không BL-caller) ⇒ collect-thread.
### ★ WALL (empirical, re-confirms note 57 §10-11)
- Sign-path 0x9ecc0 **KHÔNG gọi** collect (0 MediaDrm JNI). Cold-drive & real-ctx-drive collector đều crash **trước** JNI: `this` cần vtable hợp lệ. Config-ctx [0x1f4a60]=0x12517558 nhưng [ctx]=0x7377 (không phải vtable). Collector once-guard [0x1fc220]=0 (chưa chạy).
- ⇒ collector `this` = object riêng trong **object-graph MSManager.init** (CFF-interdependent). Note 57 §11: piecemeal call → loop/fail; **emulation-probing KHÔNG yield thêm**.

## 3. ĐƯỜNG TIẾP (cần tài nguyên ngoài session offline)
- **(A) Windows tt.Harness** → lấy config/init-sequence thật (app gọi MSManager.init native từ MSB_* + bundle device_id=7678616678053643790/dyn_seed/install_id/app_id=1233/license) → replay Mac. Well-defined, transfer nhỏ. **Khuyến nghị nếu muốn full-772.**
- **(B) Multi-week CFF-devirt** init 0x5ed34 + config 0x4f3b0 + object-graph → dựng collector `this`. Tốn.
- **(C) Accept** — core T10-validated không cần #24.
- Fast-inject #24 vào report = DEAD-END (không có #24 value thật; server reject token giả).

## 4. Artefacts/tools
- `huongB_devirt19/_vm_symexec.py` (VM tracer), `_vm_static_decode.py` (⚠ bias 0, cần −0x9b374), `_vm_reloc_resolve.py`.
- `ground-truth/vm_symexec_1814f0_trace.txt` (trace + op44 nested + 9 emit).
- `signer/` tt.Dump: sign đầy đủ = `gradle -q dump -DFIXTIME=1717600000`; recon widevine = thêm `-Dwv=true` (globals dump + ctx-drive + JNI-site markers @0x1231e4/0x1232cc). `gradle -q run` = tt.LoadTest (stall config, đừng dùng cho sign).
- Env: `~/.re-venv` (unicorn 2.1.4 + capstone 5.0.7); JDK21=/opt/homebrew/opt/openjdk@21.

## 5. BOARD: BATON=human (chốt-chặn chống burning-loops). Quyết định: A / B / C.

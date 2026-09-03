# AI BOARD — cây gậy tiếp sức (relay)

BATON: human           # C3(1): #24/MSManager.init re-confirmed WALL. Collector `this` not a global (real ctx [0x1f4a60]=0x12517558, [ctx]=0x7377 not vtable→crash); once-guard [0x1fc220]=0 (collector never ran). Note 57 §10-11: config only via full app-sequence, piecemeal loop/fail, emulation-probing won't yield. Real paths: (A) Windows tt.Harness config-seq, or (B) multi-week CFF-devirt. Core T10-validated w/o #24. HUMAN: pick A/B or accept.
ROUND: 1
# --- prior ---
# 🎉 OFFLINE SIGNER WORKS ON MAC: tt.Dump emits real X-Argus(388)/Gorgon/Khronos/Ladon: tt.Dump emits real X-Argus(388)/Gorgon/Khronos/Ladon from (url,header_block)+device-store via real libmetasec (unidbg), clock lockable (FIXTIME). Byte-exact impossible (random IV). Phone genuine=772; +384 = device-state attestation (#24 dyn_seed) gated on get_seed network(MSB_NET)+keva d8b674 = last increment, NOT a code wall. Note 57 s5. DONE.
ROUND: 1



### 2026-09-03 claude (solo)   STATUS: done — symbolic-exec engine `_vm_symexec.py` built + verified; ★handler-table BIAS correction

**Deliverable (C1 phase-3, user chose symbolic-exec path):** `huongB_devirt19/_vm_symexec.py` — unicorn-driven VM replay/disassemble-by-execution of report-builder prog **0x1814f0** (interp 0x52924, enter via caller 0x95a3c). Applies all 6765 RELATIVE relocs, derives handler-set from emulator RAM, resolves op44 two-level dispatch, PLT-by-name (malloc=bump-alloc), guards null native-callouts.
**VERIFIED:** full trace 605 handler-steps (span bcp 0x1814f0→0x186690), 121 op44-nested, 9 native callouts, terminates on trap. Output `ground-truth/vm_symexec_1814f0_trace.txt`. Run `~/.re-venv/bin/python _vm_symexec.py --steps 40000`.
**★ CORRECTION (only dynamic replay exposed):** runtime `handler(op)=table_base[op]−0x9b374`. Prior `_vm_static_decode` used bias 0 → all its handler VMAs were +0x9b374 PHANTOM. So earlier "op44=0xedec0 computed-branch+sleep_for anti-emu" analysed the WRONG function. **Real op44=0x52b4c = 2-level dispatch escape** (sub-op=(word>>6)&0x3f via table `*(0x1f00e8)`); no anti-emu sleep. IR word=4B.
**★ pskVersion emit = NATIVE-CALLOUT layer, not a VM branch:** builder makes 9 `emit(self,data_ptr,len)` callouts (invoker 0x9b5cc). Which fields emit (incl #18/#19/#20 pskVersion) decided by callouts. Offline synthetic state ⇒ all callouts null → offline boundary = state-gated (matches user's 1-time-capture model).
**Next (tooled):** feed captured interp entry-state (x0 report-ctx graph at 0x95a98 `bl 0x52924`) into `_vm_symexec.py` → differential real-state ↔ zero-state → pskVersion gate. Note 59 §session-7.


### 2026-09-02 claude (solo)   STATUS: blocked→human — .mss (mssdk_setting) advanced: AES-256-ECB write-primitive SOLVED, inverse-pipeline behind CFF/VM+logger wall

**MỚI (con đường disasm-setup như .msp, không lặp black-box):**
- Getter kind1 disasm 0x1184d0 LEGIBLE: param x2 = **chuỗi RỖNG** (rodata 0x19bb7e byte đầu NUL — SỬA "IV-từ-rodata" §10). Call `0x10c158(input=file, key=MD5(SHA1(keyname))=5961b616…, "", &outlen, w4=0)` → 0x15009c (chỉ std::string move, KHÔNG decompress).
- **FAITHFUL EMULATION** `_mss_emu.py` (harness `_msp_emu3.py`, init_array 147/147): 0x10c158 reached-RET; **mode-probe ⇒ AES-256-ECB ENCRYPT chuẩn** (3 khối giống→out giống, khớp `_aes_pure.encrypt_block` byte-exact; w4 KHÔNG đổi direction). 0x118400 = **WRITE path** (fopen/fwrite 0x12e79c) ⇒ on-disk = ENCRYPT(plaintext); `.msp` giải được vì RC4 đối xứng, `.mss`=AES ⇒ cần INVERSE.
- **Loại trừ SẠCH (pure-python)**: ECB/CBC/CTR/OFB/CFB toàn-file × mọi IV/alignment/embedded-IV/outer-RC4 → rác. ⇒ on-disk ≠ AES(key,plaintext) mode chuẩn ⇒ có container-framing/EVP-mode-wrap (jumptable 0x18fa28) mà direct-call bỏ qua.
- **Trần thật**: getter 0x1182d0 + crypt 0x10c158 đều **CFF-flattened + VM-dispatch** (blr 0x11877c/0x1119c8). Decrypt-branch nằm trong graph phẳng, không phải sibling legible.

**DECISION (human) — 3 hướng cho `.mss` (giá trị PHỤ, device-secret đã xong):**
1. **Accept** — `.mss` characterized đầy đủ (AES-256-ECB, key universal MD5(SHA1(keyname)), write=encrypt, inverse=cần pipeline). Đóng store-family.
2. **Heavy full-getter emulation** — vượt logger singleton [.bss 0x1fbaf8] (prior thử 3 cách FAIL) để read-getter tự decrypt+parse container. Nhiều ngày, rủi ro cao.
3. **Capture-once live** — hook read-getter trên phone lấy plaintext (cần thiết bị). Nhanh nếu có phone.

Deliverable: `_mss_emu.py` (faithful AES-256-ECB oracle + 6-arg 0x10c158 harness). Note 56 §12. `.msf3`=XXTEA✓ `.msp`=RC4✓(crown jewel) `.mss`=characterized.

---

### 2026-09-02 claude (solo)   STATUS: done — .msp device-secret STATIC-DECRYPT CRACKED (pure-python RC4)

**KEY-DERIVATION (disasm 0x118438/0x118448 = hash LỒNG NHAU):** `key = MD5( SHA1(keyname) ).hexdigest()` (32 ASCII) = `MD5(bytes.fromhex(filename)).hex()` ⇒ chỉ cần FILENAME. ~120 ứng viên MD5(name)/SHA1(name) ĐƠN trượt vì key là hash lồng.
**CIPHER `0x10bbd0` = RC4** (emulated keystream == `rc4(key)` byte-exact). ⇒ decryptor PURE-PYTHON, no emulator.
**Format:** `inter = ct XOR RC4(key) = [4B LE decompressed-len][zlib]` → `zlib.decompress(inter[4:])` = JSON.
**VERIFY:** .msp_092(sdi_v2) len-header 468==468 JSON settings; .msp_589(device-secret) 494==494 → kiid=ef86fe33…, fltk=1787822601249, dyn_deviceid=7678616678053643790 KHỚP known. MD5(SHA1(sdi_v2))=69c65eb5=tên file plaintext.
**Đường tới lời giải:** emulator VM `_msp_emu3.py` (init_array 147/147 → thunk 0x1119c8 emulate SẠCH, vượt note-39) cho keystream tham chiếu → nhận diện RC4 + rút key-deriv; rồi thay pure-python.
**Deliverable:** `huongB_devirt19/_msp_decrypt_static.py` (stdlib, no deps). Follow-on nhỏ: .mss(mssdk_setting)=kind khác. .msf3=XXTEA xong. Note 56 §9.

---

### 2026-09-01 claude (solo)   STATUS: checkpoint→human — .msp/.mss static-decrypt: cipher đặc tả trọn, key VM-gated, emulator vượt wall VM (note 56)

**Task:** ".msp/.mss fully-static decryptor" (user chọn). Verify vs `cap.noindex/gt_live/.msp_*` THẬT.

**ĐẶC TẢ CIPHER (3 bằng chứng độc lập — note 56 §2):**
1. length-preserving: `len(zlib(json,level1))==len(file)` chính xác (092: 272=272, 589: 375=375) ⇒ stream, không nonce/tag/IV trong file.
2. XOR position-fixed: head bytes[2..5]=`7a642260` giống hệt giữa 2 capture khác thời điểm của .msp_092 (pt[2..5]=`00 00 78 01` bất biến). ct_092^ct_589 tại [0..1]=`b8d0`≠0 ⇒ key per-keyname.
3. khớp static-lift note-54 (mode3 driver 0x15a598 = stream length-preserving, STOREHIT=0).
⇒ file = XOR-stream( `[4B LE decompressed-len][zlib magic 78 01]` ).

**KEY VM-GATED (black-box ~350 tổ hợp ÂM TÍNH — note 56 §3):** XOR-lặp / hash-CTR / MGF1 / HMAC / RC4 / AES-CTR/OFB/CFB với key∈{keyname-hash, const c1167e…, K1..K7/K32 nhúng, 3 dev-key} × IV × mode — 0 trúng. Ghidra: `0x10bbd0`(crypt) & `0x10b010`(keymat 20B) đều CFF + `blr 0x1119c8` VM.

**EMULATOR OFFLINE (deliverable, vượt wall note-39):** `_msp_emu3.py` + `_plt_map.json`(165 import từ .rela.plt) + `_aes_pure.py`. Chạy `.init_array` **147/147 ctor sạch** (bản cũ `_msp_emu.py` bỏ init + PLT stub địa chỉ SAI → spin). **VM thunk 0x1119c8 emulate tới `ret` KHÔNG diverge.** Last-mile: (a) wrapper 0x12f290 spin ở singleton lazy `.bss 0x1fbaf8` (không do ctor dựng); (b) emulate thẳng 0x10b010/0x10bbd0 tới RET nhưng output std::string chưa đúng (ABI sret x8 + globals VM). Env: venv `~/.re-venv` unicorn 2.1.4.

**Next (well-defined, note 56 §6):** B1 emulate 0x10bbd0 trực tiếp + read-trace globals (⇒ phân định static-thuần vs device-gated); B2 emulate 0x1182e0(keyname) + fopen/fread stub; B3 devirt CFF (nặng). Không chặn deliverable: plaintext .msp có qua capture-once; .msf3 XONG.

---

### 2026-09-01 claude (solo)   STATUS: done — slot16 KHÉP LẠI (device-stable lookup value; SIGN_KEY hash BÁC BỎ; capture-once xác nhận reusable)

**Trace SM3 #19 đúng (sau reboot + spawn-gate, sửa loạt bug frida QuickJS):**
- Hook full-message SM3 `0x9fdac`(x0=data,x1=len). Bug đã sửa: `a[1].toInt32()`/`new Uint8Array`/`this.context.lr` đều "not a function" → dùng `parseInt(a[1].toString().substr(2),16)` + `ptr.add(i).readU8()`.
- Bắt 103 nonce (68B `SIGN_KEY‖nonce‖SIGN_KEY`) + 41 slot16 #19. **Cross-check: slot16 ∩ {SM3(SK‖nonce‖SK) full/[:16]/[16:]/bswap} = ∅ ⇒ 68B SIGN_KEY hash KHÔNG phải slot16 producer** (nó là OUTER-argus/X-Gorgon).
- **slot16 bị SM3 TIÊU THỤ** (mọi slot16 xuất hiện làm input SM3 len=16 + trong #19) nhưng **KHÔNG là output SM3 nào** ⇒ producer = non-hash lookup/decrypt từ device-secret (khớp Ghidra `unhex(map_lookup(registry,key))`).
- **slot16 DEVICE-STABLE xuyên session:** `46c03b52…` (session này) == GT 2026-08-29 cho /ppf/eligibility (endpoint GT duy nhất overlap → KHỚP). "per-session 139ecfd5" trước đó là từ capture MD5 SAI, bỏ.
⇒ **capture-once (`endpoint_slot16_map.json`) VALID + tái dùng xuyên session.** Note-55. Artefacts: `_sm3net.js`, `_spawn_sm3.py`, `_sm3full.js`.

### 2026-09-01 claude (solo)   STATUS: done — slot16 GIẢI TRỌN bằng Ghidra (map-stored session value, KHÔNG compute offline)

**Cài Ghidra 12.1.3 + JDK21 user-local (~/tools, no sudo) → decompile libmetasec. Gotcha: NSA không ship decompiler macOS → tự build `make ghidra_opt` (x86_64/Rosetta) → os/mac_arm_64/decompile; Ghidra 12 bỏ Jython → script Java. Xem [[ghidra-macos-arm-setup]].**

**Kết quả decompile (huongB_devirt19/_ghidra_out/fn_*.c):**
- **5 static caller của unhex 0x891f4 = store/device-secret decoder, KHÔNG phải slot16:** 0x1349ac=loader device-secret (đọc rdk2_ms/rtk2_ms/rsk2_ms, unhex rtk2_ms→26B); 0x119108=unhex+decrypt key-hằng(c1167e09a3f577f6…); 0x13ab30=reader MSSPItem_v2; 0xcaa0c=wrapper unhex; 0x887e0=thunk. ⇒ slot16 gọi unhex qua INDIRECT call.
- **Giải mã indirect call của 0x879d8 bằng runtime value trong `_slot16_gappages.json`:** `*(0x1f09d0)=0x76105071e4 −0x47d0a8 → file 0x8913c`; `DAT_002f0a20→.bss 0x1f4990` (registry). Ghidra decompile **0x8913c = std::map/_Rb_tree lookup** (comparator 0x250660, value tại node+0x30).
- ⇒ **slot16 = unhex( map_lookup(registry@0x1f4990, key) )**. Registry nạp heap per-session từ device-secret+session-seed (KHÔNG trong ảnh .so tĩnh). Giải thích: emulate 0x879d8 ra 0 hex (map rỗng), slot16 per-session (map dựng lại), pure-offline bất khả (cần map=cần session). **Capture-once là con đường offline DUY NHẤT đúng bản chất.**

Deliverable KHÔNG đổi (capture-once table vẫn là lời giải). Ghidra sẵn cho mọi RE sau này.

### 2026-09-01 claude (solo)   STATUS: done — slot16 producer CORRECTION (0x879d8 loại; narrow producer=1/5 caller unhex); deliverable KHÔNG đổi

**Chốt last-mile slot16 offline-compute bằng CHỨNG MINH emulation (unicorn 0x879d8):**
- Bắt cặp live khớp (0x879d8 onEnter ctx + slot16 CÙNG call qua input của decoder 0x891f4): `/aweme/v2/feed/`→`622f4cfce4e8f05880d322224b61364d`, `/aweme/v1/aweme/stats/`→`139ecfd50560f0e1512ccca95c642032`.
- Emulate 0x879d8 = **FILE code** (không dùng runtime-dump vì dính hook-trampoline `br x16`) + full runtime data (closure 3-level + stack + TPIDR canary) + overlay **3 gap page** (0x1ef000 GOT / 0x1f0000 .data / 0x1f4000 bss) đọc từ CÙNG live process (base khớp 0x7610001000).
- **Read-trace: still-missed pages = {} (input HOÀN CHỈNH, 0 uncovered read)** → emulate tới `ret 0x87cf4` → **sinh 0 chuỗi 32-hex nào**. ⇒ **0x879d8 KHÔNG build slot16-hex ⇒ KHÔNG phải producer** (memory `[[slot16-token-native-prf]]` ghi "producer=0x879d8" SAI → đã sửa qua `[[slot16-producer-not-879d8]]`).
- **0x891f4 = UNHEX generic** (5 caller `bl 0x891f4`). Producer thật = 1 trong 5 hàm chứa caller: `0x887e0, 0xcaa0c, 0x119108, 0x1349ac, 0x13ab30`. Next (tuỳ chọn): hook 0x891f4 + backtrace lọc input hex=32-char-nonzero → xác định caller slot16 → reverse/emulate hàm đó.
- **slot16 PER-SESSION** (cùng endpoint /aweme/v1/aweme/stats/ = 139ecfd5 nay vs 3016f60d bản 08-29) ⇒ dù crack full vẫn phải re-derive mỗi phiên ⇒ **capture-once là model tự nhiên**, KHÔNG block deliverable.
- Framework tái dùng: `_slot16full.js` (capture cặp), `_slot16verify.py` (emulate+read-trace+gap-overlay), `_slot16_gappages.json` (3 gap page). Env: `sudo mdutil -a -i off`.

### 2026-08-31 claude (solo)   STATUS: done — store cipher = XXTEA, reversed + verified

**CRACKED (A→devirt offline sau khi B lộ đường):** store `.msp/.mss/.msf3` = **XXTEA**, delta `0x9E3779B9`, core **0x152310**(x0=in, x1=byteLen, x2=key16, x3=&outLen). Packing = LE u32 words + APPEND byte-length word; rounds=6+52/n. Key = **16B per-value** (nguồn x2 = [arg1+8] của wrapper 0x10dce0).
- **Verify:** `_store_xxtea.py` encrypt/decrypt round-trip khớp byte-exact 2 cặp live: key=a9aa231e… pt="1777072748" ct=c91146d3f646a4b7b2fb1e4cfca5251f; key=62e2ee76… pt="300" ct=b8ebf6e291092c22. Cả encrypt lẫn decrypt OK.
- **Chuỗi ghi:** handler 0x12fd3c → wrapper 0x10dce0 (gọi XXTEA 0x152310) → write 0x12eb3c → blr resolve runtime→0x12e79c (fopen 0x16facc+fwrite 0x171c58+fclose) → `.msdata/mssdk/ov/<prefix>_SHA1(logical_key)`.
- **KDF filename XÁC NHẬN:** SHA1(logical_key); logical key = sprintf("%s-%d-%d-",…). SHA1("sdi_v2")=092fde7a=.msp; SHA1("3019-0-1-<md5>")=5a78573b=.msf3.
- **Cách crack:** hook write-blr 0x12ebfc (target runtime=0x12e79c) → disasm offline → thấy delta 0x9e3779b9 = XXTEA → hook 0x152310 lấy (key,pt,ct) → reproduce.
- **SỬA memory cũ:** "store=AES" SAI — AES subsystem là request-signer; store là XXTEA. (Vì vậy byte-match qua 8 hàm AES luôn NONE, brute AES trượt.)
- **Follow-on tuỳ chọn (fully-static):** derivation 16-byte per-value key (không phải MD5 đơn giản của pt/device_id/logical-key) — trace nguồn x2 hoặc hook 0x152310 để lấy key on-demand.

Artefacts: `_store_xxtea.py` (deliverable), `_xxtea.js`+`_xxtea_out.json` (key/pt/ct capture), `_blrwrite.js` (write-blr resolver), scratchpad/meta_disasm.txt (disasm cache). Anti-tamper: chỉ function-hook OK, svc-hook giết app.

### 2026-08-31 claude (solo)   STATUS: blocked → BATON:human (mapped full store-access architecture; crypt behind indirect vtable dispatch)

**Track C — ĐÃ MAP TRỌN đường truy cập store (bằng path-builder backtrace + objdump offline), nhưng chưa rút được key/plaintext:**

CHUỖI GỌI: `store-manager 0xddac8` (dựng path: dir `.msdata/mssdk/ov/` + `.msp_/.msf3_` + SHA1(preimage)) → gọi `dispatcher 0x12f990` ×2. Dispatcher: dựng logical-key `sprintf("%s-%d-%d-", keyname, n1, n2)` (⇒ **SHA1 preimage = `"<key>-<d>-<d>-"`, KHÔNG phải bare keyname** — sửa KDF cũ) → lock → lặp danh sách handler → tại `0x12fa48 blr x8` gọi `vtable[1]` mỗi handler.
- Handler cụ thể bắt được: `0x12fb50` (float rate-limiter, KHÔNG crypto), `0x12fd3c` (gọi cụm file-I/O 0xe0d9c/0xe1070/0xe11d0 kề RDR 0xe2df0 ⇒ **handler persist thật**), `0x13accc`.

**5 CHỨNG MINH quyết định (đã loại trừ, có data):**
1. Store ct trên đĩa (kể cả file ổn định 16/32B) đi qua **0/8 hàm AES đã hook** (`_store_match.js` byte-match=NONE). 0x15a628 = firehose ký request.
2. 3 raw key bắt được (`8252970d`,`b8d72dde`,`b114249b`) **KHÔNG decrypt** store (brute mọi mode/IV; b114249b chỉ false-positive padding 0x01).
3. Store I/O **KHÔNG qua libc** (open/write/syscall-wrapper=0 event) — **188 svc inlined** (nr nạp động). Blanket-hook 188 svc (kể cả onEnter rỗng) **GIẾT app ~t5s** = anti-tamper .text. **Function-hook thì OK** (bắt 4000 op, app sống).
4. Memscan RAM: ct store **không tồn tại** (buffer freed nhanh); plaintext marker `mssdk_setting/sdi_v2` cũng vắng. (device_id=7678616678053643790 + JSON mạng CÓ → login nguyên.)
5. Static call-graph BFS (bl-only) từ handler **KHÔNG reach vùng AES** — vì dispatch qua `blr`/`br` indirect, chỉ runtime mới resolve.

**Emulator flaky:** frida detach hay treo (timeout 2min); dùng `os._exit(0)` trong driver. frida-server phải chạy **root** (chạy nhầm `shell` → PermissionDenied). Store ghi mỗi launch ~t20-40s dù UI kẹt splash (GPU emulator 33s/frame, KHÔNG phải hang).

**2 hướng còn lại cho pha sau (cần người chọn):**
- (A) **OLLVM devirt OFFLINE** handler 0x12fd3c + callee (0xe1070/0xe11d0/0xca000) trên `bin/libmetasec_ov.so` (Ghidra/IDA) — theo indirect-call bằng phân tích tĩnh sâu để tìm hàm crypt + KDF key/IV. Đúng tinh thần "static-lift làm deliverable". Disasm cache sẵn: scratchpad/meta_disasm.txt.
- (B) **Trigger WRITE có kiểm soát** rồi hook đúng handler persist khi nó fire: đổi 1 setting/đăng xuất-nhẹ (KHÔNG re-register) để ép mssdk ghi store, đồng thời hook 0x12fd3c + 0xe1070/0xe11d0 + deep-follow buffer → bắt (plaintext,ciphertext,key). Handler persist chưa fire trong các cửa sổ read-only vừa rồi.

Artefacts session này (huongB_devirt19/): `_store_match.js/_match_drive.py` (byte-match oracle), `_svc.js` (svc catcher — chứng minh anti-tamper), `_storemgr.js` (path-builder backtrace → call chain), `_handler.js/_deep.js` (vtable handler dump), `_fio.js` (file-I/O hook), `_offline_verify.py` (mode-prover, sẵn khi có key+iv+in+out). Memory: [[store-crypt-not-aes-firehose]], [[store-io-inlined-svc-antitamper]].

### 2026-08-30a claude (solo)   STATUS: rework (đang thực thi Path A)

**Resume Track C Path A (attach-by-pid oracle) — hạ tầng đã thông:**
- frida-python 17.17.0 == frida-server on-device 17.17.0 (venv `~/.frida-venv`). Transport OK sau khi restart frida-server (`enumerate_processes`=111 procs; NPE-quirk cũ tự hết).
- Oracle `_store_key_grab.js` v2 (Frida-17-safe: `enumerateModules`, deferred install, rpc `dump`/`status`) — hook RDR(0xe2df0)→arm 150ms→KSCH(0x1591bc, đọc key@x1[x2])+EINIT(0x159d60, key+IV)+block prims in-window. Driver mới `_grab_attach_pid.py` (attach pid, KHÔNG spawn; swipe feed 40s; pull full log→`_grab_out.json`).
- **BLOCKER gặp & cách xử lý:** emulator-5554 kẹt — system_server ANR-storm + binder contention ⇒ TikTok crash-loop (pid đổi liên tục 26965→27728→29244) ⇒ frida attach `TransportError/ProcessNotResponding` (inject vào process đang chết). Restart frida-server KHÔNG đủ (framework mới là thứ wedged). ⇒ `adb reboot` (giữ /data). Đang chờ boot_completed (dexopt lại TT 136MB ⇒ chậm).
- **Next:** boot xong → `su 0 frida-server &` → `am start` alias Splash (chạy nền, đừng chờ) → poll pid **ỔN ĐỊNH 20s** (thoát crash-loop) → `_grab_attach_pid.py 45` → DIFF (key,iv,ct) vs ground-truth store bằng `_gcm_verify.py`+AES modes.


### 2026-08-29k claude (solo — KHÔNG có codex)   STATUS: rework → BATON:human (static-lift XONG phần thuật toán; chờ emulator cho 1 giá trị key)

**Tiếp card j — trả lời "còn phần nào nữa" bằng 4 chứng minh tĩnh QUYẾT ĐỊNH (đọc thẳng .so, không đoán):**

1. **Toàn hệ AES đọc 0 global device/.bss.** Quét adrp trong dispatcher `0x10d064`+`0x10db6c`, keysched `0x1591bc`, 3 driver `0x159d60/0x15a1dc/0x15a598`: chỉ chạm rodata tĩnh `0x111000`(thunk) `0x18f000`(jumptable) `0x196/197`(Te+sbox+Rcon) `0x198/199`(Td) `0x19b000`(string). **KHÔNG có target ≥ 0x1f0300 (file-end).** ⇒ crypto tất định theo input, device-binding KHÔNG nằm trong thuật toán.

2. **KHÔNG có key hằng trong .so.** 8/8 callsite `bl 0x1591bc` nhận `userKey`(x1) từ **dữ liệu runtime**: dispatcher → `x1=[[x20+8]+8]`; driver → `mov x1,x0`(key=tham số hàm). Không callsite nào nạp key từ adrp rodata ⇒ không hardcoded-key.

3. **Layout key chốt được:** `key = ctx->[8]->[8]`, `keyBYTES = ctx->[8]->[4]` (∈16/24/32), `IV = driver arg x3`. ⇒ chỉ cần đọc **x1[x2] khi vào `0x1591bc`** = trọn key+độ dài trong 1 hook.

4. **Filename = SHA1(keyname)** (GIẢI pending#5): getter dựng path qua `0x10b13c/0x10b010` (SHA-1, `w0=#0x14`=20B) rồi builder `0x1509c0(fmt="%s/%s%s" @0x1909a0, ...)` + hậu tố `.msp_`. `msp_092f/589c`, `mss_9b8e` = SHA1(logical-key) cắt hex.

**Đính chính card j:** `0x10dce0` KHÔNG phải AES trực tiếp — nó là **wrapper record/buffer** (5 callee `0x14fa94/152310/14fad8/15009c/14fe34` chỉ malloc/free+string, không gọi keysched). AES thật = **EVP dispatcher `0x10d064`/`0x10db6c`** (gọi keysched tại `0x10d0c0`/`0x10dbac`).

**Trạng thái deliverable:** "static-lift làm deliverable" — **phần THUẬT TOÁN đã XONG 100%** (AES + bảng + keysched + 3 mode + filename-KDF). Còn **đúng 1 giá trị dữ liệu**: bytes key (device-bound hay không CHƯA rõ vì tầng dựng ctx nằm trên, nghi SHA1). Lấy bằng oracle 1-hook.

**Oracle rút gọn:** `huongB_devirt19/_aes_oracle.js` (đã thêm hook do-cipher `0x159618/0x15997c` bắt in/out cùng key+IV → DIFF 1-shot). Read-only, spawn, **KHÔNG re-register**.

**Chặn (không đổi):** emulator DOWN (`adb devices` rỗng; frida host chưa cài). User đã chọn (A). Turnkey khi bật máy:
```
emulator -avd <avd> &          # hoặc AVD đang có
adb wait-for-device
pip install frida-tools; # + push frida-server khớp abi/version vào /data/local/tmp && chạy
frida -U -f com.zhiliaoapp.musically -l huongB_devirt19/_aes_oracle.js   # spawn, KHÔNG -n/attach-reregister
# kích store I/O (mở app) → thu key(x1)+keyBYTES+IV → tái lập AES offline → DIFF _msdump/*.bin
```


**Δ cùng phiên (đào tiếp static frontier — trả lời dứt điểm "key sinh ở đâu"):**
- Global `[0x1f2d70]` mà getter đọc = **C++ singleton 44B dựng từ rodata TĨNH** (`q0/q1/d2 ← 0x192f00/f10/f70`, ctor 0x178fdc, guard 0x13db04–0x13db2c) ⇒ path-prefix tất định, KHÔNG device-bound.
- Getter `0x1182d0` = open-record-by-keyname: tính **2 digest** (0x10b13c w1=0 → sp+0x50; 0x10b010 w1=1 → sp+0x40), rồi **switch mod-3** (3 loại store msp/mss/msf3) → nhánh gọi `0x10bbd0(digestA,digestB)`.
- **`0x10bbd0` (và anh em mod-3) chạy trên OLLVM-VM**: `blr [0x111000+0x9c8]=0x1119c8` (thunk trung tâm) + opaque-predicate (madd+nghịch-đảo-modular) + fake `sub sp`/`br x23`. ⇒ **KEY AES được sinh BÊN TRONG lớp VM này.**
- 9 callsite `bl 0x1591bc` đều thuộc cụm crypto (0x10d0c0, 0x10dbac + 7×0x159xxx); KHÔNG cái nào ở getter ⇒ getter nạp key qua fn-pointer/VM, không bl trực tiếp.

**Kết luận "còn phần nào nữa" (đóng khung dứt khoát):** phần THUẬT TOÁN đã lift xong 100%. Ẩn số DUY NHẤT = **bytes key AES**, nằm trong OLLVM-VM store-layer. Hai khả năng loại trừ nhau: (a) key=H(keyname[+tĩnh]) → forge offline 100%; (b) key=device/session secret → cần 1 oracle read. Phân biệt (a)/(b) chỉ bằng: **devirt VM subtree (path B, nặng)** HOẶC **1 oracle read tại 0x1591bc (path A — user đã chọn, chờ emulator)**.


### 2026-08-29j claude (solo — KHÔNG có codex)   STATUS: rework → BATON:human (chờ emulator cho oracle)

**★ ĐẢO KẾT LUẬN card i: cipher = STANDARD AES 100% (không phải "custom const-inlined").**
Card i nói "không có bảng AES" là **FALSE NEGATIVE**: bảng lưu dạng **word-giãn-lane** (`00000063` thay vì byte liền `637c777b`) nên grep trượt.

**Bằng chứng cứng (offline, đọc thẳng .so):**
- `0x1591bc` = **AES key-schedule THẬT**: `Nr=keyBYTES/4+6` (10/12/14), `rev` big-endian, nhánh `cmp #0x20/#0x18/#0x10` (256/192/128). Arg: `(AES_KEY* x0, u8* userKey x1, int keyBYTES w2)`.
- 5 bảng tại `0x196fbc/0x1973bc/0x1977bc/0x197bbc` (sbox 4 lane) + `0x197fbc` (**Rcon** 1,2,4,8…). **Trích lane-0 → 256 byte KHỚP TUYỆT ĐỐI sbox AES chuẩn** (verify python `sb==std`).
- Decrypt Td-tables tại `0x198/0x199/0x19a`; block-decrypt `0x159618`,`0x15997c`.

**Kiến trúc EVP (dispatcher `0x10d064`/`0x10db6c`, gọi qua vtable con trỏ hàm):**
- Jump-table `ctx->mode`(0..3) tại `0x18fa24`=`00 06 0d 14`, `0x18fa2c`=`00 07 0f 17` (offset×4).
- mode0=key-init; **mode3 driver `0x15a598` zero counter `ctx+0x1f8` = STREAM (CTR/CFB/OFB), length-preserving** → khớp store-file KHÔNG ÷16. mode1 `0x159d60`, mode2 `0x15a1dc`. Init lưu keysched(488B)@ctx+0 + IV(16B)@ctx+0x1e8.

**Bài toán thu hẹp:** thuật toán = AES đã biết + bảng đã lift. Chỉ còn **(key, keyBYTES, IV, mode)** — đều device-bound/runtime. Đọc 1 lần:
- key+keyBYTES @`0x1591bc`(x1,w2); IV @driver(x3); mode xác định bằng **DIFF offline** (thử CTR/CFB/OFB/CBC-decrypt vs `_msdump/`).
- Oracle sẵn: **`huongB_devirt19/_aes_oracle.js`** (hook keysched+3driver+reader+getter, read-only, KHÔNG re-register).

**Chặn:** emulator DOWN (`adb devices` rỗng, no qemu). User đã chọn (A). Bật `emulator -avd tt_root` + frida-server → `frida -U -f com.zhiliaoapp.musically -l _aes_oracle.js` (spawn), kích store I/O, thu key/IV → offline AES + DIFF. Sau đó deliverable = decrypt thuần offline cho device này.

### 2026-08-29i claude (solo — KHÔNG có codex)   STATUS: blocked → BATON:human (fork quyết định)

**Đóng nhánh ciphertext-only bằng SỐ LIỆU (thuần offline, DIFF trên `_msdump/`):**
- Cross-file XOR giữ entropy cao (6.41/6.17/7.19), low<0x20 ~0.10–0.15 (≈random 0.125), printable ~0.37 → **KHÔNG keystream-reuse**.
- Autocorrelation không chu kỳ (đỉnh 0.03 trên 96B = nhiễu); 0 dup block-16B. Kích thước 314/262 KHÔNG ÷16.
- ⇒ **stream cipher mạnh, nonce/IV per-file duy nhất. Tấn công chỉ-từ-ciphertext = BẤT KHẢ.** 3 file + ~PT[0]=0x08 không đủ trích keystream.

**Định danh cipher (đảo lỗi grep line-wrap của phiên trước):**
- Kiểm nghiêm (`grep -o|wc -l`, `python.find`): **KHÔNG có** bảng AES S-box/Te0, SM4 S-box/CK, ChaCha "expa" → không phải cipher chuẩn; keystream **custom const-inlined**.
- MD5(`0x15b594`)+SHA1(`0x15cd34`) CÓ thật (IV+padding rodata `0x19b3f0`/`0x19b500`/`0x19b510`) NHƯNG chỉ là **hash-util tổng quát/filename-KDF** (`0x10b010`/`0x10b13c`, 15+ caller mỗi cái). **KHÔNG có caller MD5/SHA1 trong vòng XOR** ⇒ keystream KHÔNG phải hash-CTR của 2 primitive này.

**Bản đồ path (để oracle hook 1 dòng khi có emulator):** reader slurp `0xe2df0` (single caller `0xf9530`@`0xf94ec`) → cache rwlock `0xe8338`. Store-getter ứng viên (gọi CẢ MD5+SHA1): **`0x117xxx–0x119xxx`** và **`0x12fxxx`**. `0x10dce0` = dispatcher OLLVM-flatten (magic 0xaf28/0xca45) — KHÔNG phải cipher.

**Tường:** key+nonce device-bound (đã chứng minh device-key A ≠ hằng .so) + OLLVM control-flow-flattening bọc keystream-gen. Ciphertext-only đã chết ⇒ deliverable BẮT BUỘC lift key/nonce-derivation từ code.

**FORK cần USER quyết (BATON:human):**
- (A) **ORACLE** — bật emulator (`emulator -avd <avd>` + frida-server) → spawn+read tại call decrypt: đọc cipher-id + key + nonce → tái lập offline + DIFF `_msdump/`. Nhanh, chắc. **KHÔNG re-register.** Chặn hiện tại: emulator DOWN (adb rỗng, no qemu).
- (B) **DEVIRT tĩnh** OLLVM store-getter + keystream-gen + device-key KDF: nhiều ngày, vẫn có thể chạm root device-derived cần 1 lần đọc runtime.
- Lưu ý: dù A hay B, "device-forge capable pure-offline" vẫn cần lift white-box device-input→key.

### 2026-08-29h claude (solo — KHÔNG có codex)   STATUS: rework → CHECKPOINT NGƯỜI DÙNG (đã định vị KHO PERSISTED mã hóa; phát hiện reframe làm đổi bài toán)

**ĐÃ tìm ra "nếu stored" của fork BOARD:** device-state của libmetasec_ov nằm ở `/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov/` (đọc bằng `su 0`, run-as fail vì app không debuggable; thuần đọc, KHÔNG đụng login):
- `.msp_589c…` 314B **H=7.35 bit/byte** (mã hóa), `.mss_9b8e…` 262B H=7.24, `.msp_092f…` 96B H=6.23 → **blob mã hóa**, đủ chỗ chứa device-key A(32B).
- `.msm_cache/.mast` 16B = ASCII `"1787843438522,2\n"` = timestamp+counter, KHÔNG phải secret.
- `.msf3_5a78…` 16B = a8832d11… (token device khác, ≠ slot16); `.msf3/.css` 8B = counters.
- `.dy/tasks/{229,539}/.t` = **protobuf** task-descriptor: session-token 16 ký tự (EAGWA35bl80b1auz / EH+TA35bn8F25tK1, chung mảnh "A35b"), endpoint `/ri/report`.
- **KHÔNG có string Keystore/Keymaster/TEE**; strings crypto (aes/sm4) VẮNG; tổng chỉ 3504 strings/2MB ⇒ **string-encryption** ⇒ nghiêng **white-box in-.so** (không phải TEE) — offline về lý thuyết khả thi nhưng phải bẻ.

**REFRAME QUYẾT ĐỊNH (lý do checkpoint):** slot16 = **device-constant, ⊥ message** (đã chứng minh ×42 capture). ⇒ "tính slot16 từ số 0" KHÔNG lợi hơn "capture 1 lần" cho offline-signer 1-device: cả hai đều cần chạy app 1 lần trên device. "Từ 0" chỉ có nghĩa khi muốn sinh slot16 cho device CHƯA từng chạy = bài toán khác (forge device), tốn nhiều ngày bẻ white-box + rủi ro chạm root device-derived, và nhạy cảm phạm vi.

**HỎI NGƯỜI DÙNG 3 hướng:** (A) chốt capture-once hoàn tất P3 [rẻ, đủ]; (B) hook runtime trích plaintext device-secret khi app giải mã .msp/.mss [đúng "đọc file+giải mã", spawn-safe, vẫn per-device]; (C) bẻ white-box decrypt .msp/.mss từ 0 [nhiều ngày, rủi ro]. BATON→human để chọn.

### 2026-08-29g claude → codex   STATUS: rework (sub-task ĐÀO-KEYSTORE: ĐÃ TRẢ LỜI fork = COMPUTED/derived, KHÔNG stored; đã định vị site dẫn xuất xuyên OLLVM wall bằng live FP-walk; còn lại = lift KDF flattened)

**Trả lời dứt điểm câu hỏi BOARD "file-backed keystore vs heap-computed":**
1. **Event-driven mem-scan** (hook DRV 0x9fdac, khi 32B đầu buffer == device-key A thì quét): buffer `A‖N‖A` nằm `prot=rw- file=null` = **heap ẩn danh (anonymous)**, KHÔNG file-backed. Artifact `_memscan3.js/.json` (BUF_HIT: base 0x77f4b8d000 sz 768KB, file=null).
2. **Quét toàn bộ 5987 (rw-+r--) ranges tìm A, 8015 ranges tìm slot16 → 0 hit** (quét sau warmup, sau khi buffer ký bị wipe). ⇒ A và slot16 **KHÔNG tồn tại bản plaintext bền** trong RAM (không keystore-plaintext, không heap-cache). Chỉ sống trong cửa-sổ-ký tạm rồi bị xóa (secure-by-transience).
3. **A KHÔNG phải hằng số baked-in .so**: grep `bin/libmetasec_ov.so` cho A (32B) + từng chunk 8B = **NOT FOUND**. Loại giả thuyết "A = app-version const chung". ⇒ **A là runtime-derived, device-bound, dựng just-in-time.**
4. **Loại đường libc-copy**: hook memcpy/memmove/__memcpy_chk/mempcpy đều không bắt được A (crypto OLLVM dùng inline NEON stores, không qua libc) ⇒ A materialize trong-register/NEON = de-obfuscate vào scratch buffer.

**SITE DẪN XUẤT (xuyên OLLVM/BLR wall bằng live stealth FP-walk — KHÔNG dùng Frida Backtracer vì bị anti-tamper kill; tự walk x29(ctx.fp) chain):**
```
SM3-driver DRV 0x9fdac
  ← thunk 0xa1004  (blr x8; struct-dispatch: s={+0:fn_ptr, +8:data_ptr, +0x10:len, +0x18:ctx, +0x20:result})
  ← 0x9fd24  (sub sp,#0x3d0)  builder struct-args
  ← 0x9b394  (sub sp,#0x310)
  ← 0x95a4c  (sub sp,#0x2f0)
  ← 0x8e2xx  (entry ký cấp trên)
```
⇒ Đây CHÍNH là lý do "0 BL xref / BLR-only" của SM3 core: cả tầng crypto gọi qua struct-of-fn-ptr. Buffer `A‖N‖A` (=data_ptr) được ráp trong các hàm flatten này.

**CẦN CODEX (static-lift, không cần Frida):** đọc disasm `/tmp/dis.txt` các hàm builder `0x9fd24` và `0x95a4c` (OLLVM-flatten) → tìm chỗ **materialize A 32B** (chuỗi movz/movk vào q-reg hoặc adrp→ldr từ .data/.bss rồi giải mã) + **hằng de-obfuscation** (XOR mask / seed). Mục tiêu: xác định A = f(root, const) — root nằm ở đâu (.bss offset? TLS? syscall Keystore?). Nếu root ⟶ TEE/Keymaster: repro-from-scratch BẤT KHẢ THI (đúng verdict cũ) → chốt fallback capture-once. Nếu root ⟶ .bss/.data giải-mã-được: đó là đột phá.

**Artifacts session này:** `_memscan2/3.js+json`, `_btrace2.js+json` (FP-walk chain), `_asrc/_asrc2.js+json` (memcpy null-hook), `_run_spawn.py`.
**Ràng buộc giữ nguyên:** CHỈ spawn+read, KHÔNG re-register. Frida: Backtracer bị kill → chỉ FP-walk thủ công; `Module.findExportByName(libc)` = null trong build này.

### 2026-08-29f claude (self)   STATUS: done→human (route (2) Đào-device-key: xác nhận ĐỘC LẬP qua DRV streaming-hash path — slot16 = device-constant, KHÔNG tính-từ-message; đề nghị chốt capture-once)

**Phương pháp MỚI (khác fork A — đi lối hash-driver, không lối producer-output):**
1. Hook **DRV 0x9fdac** `f(x0=data,x1=len,x2=ctx)` = SM3 streaming update/finalize (call `len<=16` = finalize/ghi digest). Ordered-dump 1 invocation producer(369): seq0=message(len lớn) → seq1=OUT16(digest) → seq2=blob-hằng 68B. Artifact: `_digkey12/13/14.js/.out.json`.
2. **Pair SẠCH không-truncate** (INV2, msglen=841 < 1600) → slot16 `6c109094…`. Test **plain-hash message**: md5/sm3[:16]/sm3[16:]/sha1/sha256 = **0/khớp**.
3. **Nghịch lý quyết định:** 2 message THỰC khác nhau (len 773 vs 841; khác `_rticket`/`ts`; 841 thêm `cdid`/`openudid`) → **CÙNG** `6c109094`. ⇒ slot16 ⊥ toàn-bộ-message.
4. **Subset brute:** 41 params bất-biến (bỏ 4 volatile) × {amp/sorted/concat-values/concat-kv} + single-field(device_id/cdid/openudid/iid/aid) = **0/khớp**. ⇒ KHÔNG phải hash-của-subset.
5. **Deref ctx (x2):** struct = con-trỏ C++ object (bc3dd961…, ổn định mọi invocation) + hằng 8B `786857617567374f`="xhWaug7O" @+0x28; **KHÔNG có 32B device-secret midstate hash-ra-slot16**. ⇒ key không lộ dạng tái-lập.
6. **Cross-session ground-truth:** `6c109094` xuất hiện **Y HỆT trong 42 file capture** (cũ 12:00 → mới 13:31). = DIFF ổn-định thực nghiệm.

**VERDICT route (2):** tính slot16 **thuần-tuý-từ-số-0 = BẤT KHẢ** (device-key gate, xác nhận lần 2 độc lập). NHƯNG slot16 = **device-constant** ⇒ **capture-once-reuse là lời giải đúng & DIFF-verified** (46c03b52=GT#2 khớp; 6c109094 ổn định ×42).

**ĐỀ NGHỊ (khuyến nghị (1)):** NHẬN capture-once table endpoint→slot16 làm deliverable route P, đóng lối tính-thuần-tuý, dồn về P3 offline-signer. Đào keystore sâu hơn = rủi ro re-register, verdict×2=bất khả ⇒ không nên.
KHÔNG re-register.

### 2026-08-29e claude (self)   STATUS: progress→user-decision (fork-A THỰC THI: slot16 = hằng-số device-keyed theo endpoint; DIFF ground-truth GT#2 46c03b52 KHỚP)

**Đã làm (fork A — live-hook tối thiểu, spawn giữ login, KHÔNG re-register):**
1. Hook `onEnter@0x879d8` (dump x0 ctx-head 48B + sel + url) ghép `onLeave@0x891f4` (slot16 16B) qua stack per-tid → bản đồ **url→slot16** (30 MAP, sel=369=0x171 xác nhận). Artifact: `_prod_url.js`, `_prod_url.out.json`.
2. **slot16 DETERMINISTIC theo endpoint & device-stable:** privacy_headers ×3 = `6c109094…` giống hệt; search/bubble ×2 = `f3136184…`; **`_rticket`/ts đổi giữa các call nhưng slot16 KHÔNG đổi** ⇒ slot16 ⊥ query/timestamp. GIẢI THÍCH đúng bí ẩn ground-truth 7≡8 (cùng endpoint ⇒ cùng slot16).
3. **2 endpoint khác path → CÙNG token** (`/consent/api/combine/list/v3` + `/tiktok/ppf/api/eligibility/v2` = `46c03b52…`) ⇒ preimage KHÔNG phải path, là **nhóm-config/khóa-thiết-bị**.
4. **DIFF vs ground-truth (hash19_nonzero_tuples.json):** captured ∩ GT = **1/1 token được trigger** = **`46c03b52742b3f2615a3abdf1636b754` = GT#2** KHỚP CHÍNH XÁC (GT query `source=profile&…` — path thứ 3 cho cùng token). 9 GT token còn lại KHÔNG trigger trong 60s (endpoint chưa gọi), không phải sai.
5. **Loại mọi giả thuyết hash-từ-url:** md5/sha1/sha256 của path/host/host+path/full-url/device_id/iid = **0/tất-cả**. ⇒ preimage = **device-secret trong ctx_session** (khớp memory `[[slot16-token-native-prf]]`).
6. **Bác finding hụt:** config-MD5 `0x15b594` KHÔNG sinh slot16 (`dectok∩produced=NONE`); nó **TIÊU THỤ** slot16 (md5(slot16) downstream). Bẫy out_x0(=input prefix) vs out_x2(=digest).

**Artifact offline:** `ground-truth/endpoint_slot16_map.json` (23 endpoint, 21 stable / 2 varying) = **bảng capture-once** để replay.

**KẾT LUẬN:** lớp nonzero slot16 (device-stable) **offline-reproducible bằng capture-once-reuse**, DIFF-verified (46c03b52 + cross-session). LẬT verdict "ephemeral ratchet không tái lập" cho lớp này. Tính-thuần-tuý-từ-số-0 (không capture) VẪN chặn bởi device-key gate (đúng note 38/47/52) — nhưng KHÔNG cần cho replay vì hằng-số ổn định & capture được.

**CẦN USER chốt deliverable:**
- **(1) NHẬN capture-once table** endpoint→slot16 (DIFF-verified) + slot16=0 cho ~50% gửi-zero ⇒ **phủ đủ offline-sign** ⇒ đóng route P thực dụng. *(khuyến nghị)*
- **(2) ĐÀO device-key** để tính slot16 thuần-tuý (trích keystore/ctx sâu) — trần rất cao, verdict cũ=bất khả, rủi ro re-register.
- Muốn DIFF mạnh hơn: chạy hook lâu hơn/kích nhiều endpoint để khớp thêm GT token (2..n /10).
KHÔNG re-register.

---

### 2026-08-29d claude (self)   STATUS: in-progress (USER CHỌN A — live-min ctx capture)

**Quyết định human:** chọn A — gỡ cổng no-live ĐÚNG 1 phiên tối thiểu.
**Điều kiện live (verify):** emulator-5554 online; app musically **đang chạy pid 20392** ⇒ ATTACH (KHÔNG spawn, giữ login/không re-register); frida-server pid 1787; forward tcp:47119→27042 đã set.
**Kế hoạch:** hook `onEnter@0x879d8` dump x0[0..0x100]+x1(sel 0x171)+x2+x3; `onLeave` bắt slot16 output (x0/x1/*x8); gom vài tuple qua heartbeat tự nhiên → phân tích offline slot16=f(ctx)? → seed replay call-graph đã giải mã → DIFF ground-truth.
**Ràng buộc:** KHÔNG re-register; piggyback heartbeat nền; chỉ đọc, không ghi/patch.

### 2026-08-29c claude (self)   STATUS: blocked→human (static-C giải mã XONG encrypted-call-graph; chứng minh registry .bss là HẰNG static; ground-truth chứng minh slot16⊥query ⇒ thiếu ctx runtime ⇒ DIFF offline bất khả nếu không đọc ctx live)

**Việc đã làm (option C — giải tĩnh, KHÔNG chạy live):**
1. **BẺ khoá encrypted-call-graph:** idx của mọi `blr` trong 0x879d8 = constant-fold chuỗi `and/orn/orr/add/eor` trên **self-addr 0x879d8** (link-time const) ⇒ idx = 0xffffffffffb82f58 (-4706472). 3 base bảng-gọi (`*[0x1f09d0]`=addend 0x5061e4, `*[0x1f09d8]`=0x5063c8, `*[0x1f0a20]`=0x671a38) đều **.data (file-backed)** ⇒ `target = base + idx` giải TĨNH được.
2. **Resolve 4 blr:** 0x87ee0→0x9368c & 0x880c8→0x9368c = **trampoline** (`mov x4,x30; add x4,x4,x0; mov x30,x4; ret` = return-to-lr+w0, NHIỄU); 0x884e8→**0x8913c** (`std::_Rb_tree` map/set lookup); 0x88ab8→**0x89320** (consumer thật, ăn x1=hexstr32@sp+0x198). ⇒ callee ngữ nghĩa còn **2**: 0x8913c + 0x89320 (0x89320 lại là hàm OLLVM-hardened tự-ref).
3. **Đập tan "tường .bss runtime":** arg map-lookup = global `.bss 0x1f4990` (SHT_NOBITS, KHÔNG reloc). Writer = `.init_array` ctor **0x36220** nạp từ **HẰNG mã-hoá .data 0x1f0960** (blob: 6d322ca4bdccb5e4771f… len 10/15/16 — OLLVM string-enc, giải lúc init). ⇒ registry = **static-derivable**, không phải runtime.
4. **Global entry `*[0x1effb0]`** = .got reloc RELATIVE→0x192f0c (file-backed) = input tĩnh biết được.

**Bằng chứng GROUND-TRUTH (hash19_nonzero_tuples.json, 11 tuple {query, slot16(16B), digest_std=SM3 64hex, mlen}):**
- **Entry #7 ≡ #8: slot16 = `0fa9508221ea96a1b3448f3e32caf988` GIỐNG HỆT** dù query khác (chỉ khác `_rticket`/`ts`, ~3s) và digest_std khác ⇒ **slot16 KHÔNG phải hàm của query/digest**.
- slot16 ≠ digest[:16] / digest[16:] / (⊕) cho cả 11 (0/11). 10 slot16 phân biệt/11.
- ⇒ Khớp memory `[[slot16-token-native-prf]]`: slot16 = **native PRF keyed by device/session/time-bucket**.

**KẸT (trần cứng option-C):** obfuscation đã bẻ + registry static, NHƯNG để lift→Node và DIFF 11 tuple cần **ctx runtime** (x0[0..0x100]/x2/x3 @0x879d8). Ground-truth chỉ có `query` — đã chứng minh KHÔNG đủ (7≡8). ⇒ pure-static không chạm được DIFF.
**ĐÃ THỬ:** fold idx (xong); resolve 4 blr (xong); section-map 0x1f4990→.bss + truy .init_array ctor 0x36220 (xong); dump hằng .data nguồn (xong); test slot16=f(digest) (bác bỏ 0/11); test slot16 hằng-phiên (xác nhận 7≡8).
**CẦN USER quyết (gate no-live do user đặt):**
- **A** — gỡ no-live 1 lần: hook `onEnter@0x879d8` đọc ctx (x0 struct + x2/x3) cho 1 query đã biết → seed replay offline call-graph (đã giải mã) → DIFF. Rẻ hơn unicorn-full vì graph đã map.
- **B** — chốt **slot16=0** (traffic thực gửi 0, offline đã chạy), đóng route P, dồn về P3 offline-signer.
KHÔNG force re-register (giữ login).


### 2026-08-29b claude (self)   STATUS: progress→user-decision (GHIM producer=native 0x879d8; loại constant-table; LỘ tường OLLVM encrypted-call-graph ⇒ static-lift bất khả rẻ)

**Bằng chứng TĨNH mới (capstone trên bin/libmetasec_ov.so + capture _p_birth4.out — KHÔNG chạy live):**
1. **Producer = hàm native 0x879d8** (KHÔNG phải VM). Prologue: callee-saved đủ, `add x29,sp,#0x50`, `sub sp,#0x250` (frame 592B), `str w1,[sp,#0x1c]` với **selector w1=0x171**, đọc field `x0+0x88`, stack-canary `mrs tpidr_el0`. Chain _p_birth4 (const, 16 BIRTH): frame 0x9dce8 `bl 0x879d8 (w1=#0x171)` → trong 0x879d8, tại 0x88858 `bl 0x891f4`(hex_to_bytes) với x8=x29-0x80 (sret slot16), x0=sp+0x198.
2. **slot16 = unhex(hexstr32)**; 0x891f4 = hex_to_bytes CONFIRM (nibble `sub#0x30/#0x61/#0x57`, `bfi w11,w10,#4`, `strb`). hexstr32 dựng vào **std::string @ sp+0x190** (`str x8=sp+0x178,[sp+0x190]`, data ref ở sp+0x198), **ghép tăng dần** qua trampoline loop 0x887e0 ⇒ **được TÍNH — không copy 1 field, không hằng.**
3. **Loại dứt constant-table:** grep bin (ASCII+UPPER) cả 8 slot16 capture + 2 oracle `46c03b52…`/`f31361844…` = **0 hit** ⇒ slot16 KHÔNG nhúng sẵn trong .so.
4. **TƯỜNG OLLVM (lý do static-lift bế tắc):** trong 0x879d8: (a) CFG-flatten (`cmp w23,#0x3b` state-dispatch); (b) **call-target MÃ HÓA**: `blr x9`, x9=`*[0x1f09d0]`+idx; idx trộn bằng `and`/`eor` 2 hằng 64-bit (0x00a06144_0a061440, 0xff5f9ebb_f4bf3a1c); arg lấy từ bảng-2 `*[0x1f0a20]`. RELA(R_AARCH64_RELATIVE) 2 base = module+0x5061e4 / +0x671a38 (NGOÀI ảnh 0x1f0000) ⇒ base-cao-giả + idx-âm → target thật ⇒ **không đọc callee tĩnh khi chưa có idx runtime**; (c) trampoline nhảy gián tiếp `add x1,x0,#0x34; br x1`. Đồ thị gọi bị khóa trong DỮ LIỆU.

**HỆ QUẢ:** grep-disasm THUẦN TĨNH đã tới trần cho 0x879d8. 2 đường còn lại đều đắt:
- **P-static-hard:** giải bảng-gọi mã hóa = suy diễn ký hiệu/emulate từng nhánh.
- **P-dyn (wall-free, mình chủ động):** **unicorn-emulate 0x879d8 offline** — chỉ kẹt vì THIẾU input-state thật (ctx x0[0..0x100], x2, x3) tại 1 lần gọi 0x879d8.

**CẦN USER QUYẾT (fork):**
- **A. Cho 1 phiên live TỐI THIỂU:** hook onEnter@0x879d8 dump x0/x1/x2/x3 + 256B ctx (piggyback heartbeat, **KHÔNG re-register**) → seed unicorn offline emulate 0x879d8 → lift Node → **diff oracle**. Sau khi có seed, mình chạy offline hết, né tường Frida.
- **B. Chốt deliverable hiện tại:** slot16=0 (traffic thường) ĐÃ offline qua `_sm3.js` (#19 11/11). Nonzero-slot16 gate ở device-mint. Dừng đào producer.

Giữ BATON=claude (tiến triển của mình), ROUND=4. Chờ user chọn **A/B**.

---

### 2026-08-29 claude (self)   STATUS: progress (XÁC NHẬN TĨNH độc lập: VM=orchestrator ⇒ devirt vô ích cho P; LEAD MỚI _Znwm/STL cho catch-at-birth)

**Phương pháp mới (thuần tĩnh, không AVD, không tưởng tượng — mọi số từ capstone trên bin/libmetasec_ov.so):**
1. **Auto-lift 119 handler** (`_vm_handlers.json`): tần suất ARX = add43/lsl23/madd18/sub11/asr7/mul6/and5/orr4/lsr2/ror2 — **eor = 0**. Một PRF/crypto 128-bit bắt buộc trộn bit (XOR/rot) → vắng mặt hoàn toàn ⇒ crypto KHÔNG ở trong bytecode handler.
2. **Giải toàn bộ native callout** (PLT→GOT→dynsym): 0x30610=malloc, 0x30760=realloc, 0x30590=free, 0x30b20=_Znwm(new), 0x30480=_ZdlPv(delete), 0x30930=memset, 0x30b40=std::this_thread::sleep_for(**53× trong handler** = anti-analysis), 0x309d0=abort, 0x30c10=__stack_chk_fail, 0x30850=__android_log_print. **KHÔNG import crypto nào.**
3. **Lõi VM disasm** (0x558a0..0x559f0): dispatch = `ldr w8,[x8]`→`and x8,#0x3f`(**opcode=word&0x3f**)→`add x8,x9,x8,lsl#3`(table+op×8)→`ldr x8,[x8]`→`sub x15,..`→`br x15`. Chỉ 1 indirect callout `blr x8@0x5594c` với `ldr x8,[sp,#0x38];ldr x8,[x8]` = gọi closure ảo C++ → SM3-driver (consumer/ký).
4. **Trace cũ _vm_trace10.* CHẾT**: h=0x52b4c là hằng obfuscation quanh adrp#0x52000 (0x52924), KHÔNG phải handler; bc/iw trỏ vào bảng chuỗi/hằng .rodata (0x1869e8="captcha.motion/smodel", 0x17c888=const table). KHÔNG tái dựng chương trình từ trace cũ được.

**HỆ QUẢ (quan trọng):** dập tắt hướng "lift VM nhiều tuần" trong summary — devirt vô ích cho P (đồng thuận board 08-28d qua bằng chứng độc lập). Producer P = native off-VM. **LEAD MỚI mở lại catch-at-birth**: P sống trong buffer cấp qua `_Znwm`/STL, không phải libc malloc → allocator-hook cũ bỏ sót.

**Blocker còn lại (thành thật):** chicken-and-egg arm-at-birth — offset P trong slab chưa biết cho tới khi P tồn tại; WP cả slab quá ồn. Lead `_Znwm` **thu hẹp** chứ chưa giải dứt. Kế hoạch né: 1 phiên AVD natural-burst đo phân bố offset-P-trong-slab trước, nếu ổn định mới arm WP chính xác.

**Artifact phiên này:** `_vm_handlers.json` (119 handler đã phân loại). Cần AVD cho bước sau ⇒ giữ BATON claude, chờ user OK chạy phiên live (KHÔNG re-register).

---

### 2026-08-28 claude (self)   STATUS: progress (USER CHỌN route P — RE hàm NATIVE producer; bắt đầu đặc tả arena chứa P)

User chọn **P** trong fork P/S/N ⇒ truy producer native. Kế hoạch P: (1) đặc tả vùng nhớ chứa P (region/prot/offset) [đang chạy `_p_region.js`]; (2) tìm hàm cấp phát arena 0x77e4… (bump) hoặc điểm ghi-đầu; (3) arm native-store WP "lúc sinh" (arm khi cấp phát, không phải tại driver) HOẶC mem-write trace hẹp init-burst → bắt PC producer store slot16; (4) disasm ARM64 hàm producer → lift Node → **diff oracle `46c03b52…`/`6df68ced…`/`ff9fe53b…`**. KHÔNG force re-register. Rào cũ cần né: WP-tại-driver chỉ thấy consumer memcpy (producer ở quá khứ); v18 xác nhận P được ghi >900-dispatch trước consume ⇒ producer ở init-burst.

---

### 2026-08-28 claude (self)   STATUS: blocked→human (LOẠI DỨT ĐIỂM giả thuyết "producer = VM bytecode"; producer là NATIVE off-VM ⇒ lift-VM vô ích; cần user chọn mức đầu tư)

**PHÁ NGHỊCH LÝ + LOẠI HƯỚNG LIFT-VM (phương pháp MỚI, độc lập với WP/backtrace cũ):**
1. **Nghịch lý "ring rỗng" (v10b) = ẢO, do BUG RUNNER:** `_run_probe.py` nhận `TRACE_DUMP` (ghi entries) rồi nhận `TRIGGER` ghi `open('w')` ĐÈ mất file ⇒ tưởng ring rỗng. Tracer/model KHÔNG lỗi. Viết `_vm_trace16/17/18.js` + `_run16/17/18.py` (self-contained, 1 lần ghi).
2. **Bắt được VM-stream tới consume-đầu:** `br x15 @0x55930` chạy ~1675/s; consume-nonzero-đầu sau ~531–1183 dispatch. Stream chỉ **10 handler / 10 opcode distinct**, cấu trúc PRF rõ (prologue → `op40×281` self-loop @bc=0x190cf8 → 6×block giống hệt → 2×block finalize → epilogue). Handler-map: `0x5b7e4`(op40,55%), `0x59714`(op15), `0x5ad2c`(op18), `0x59518`(op1), `0x58a54`(op38), `0x52b4c`(op44), `0x5b9b0`(op63), `0x59a3c`(op37), `0x5c0fc`(op42), `0x5a1d0`(op5).
3. **NHƯNG stream KHÔNG cô lập producer:** op-sequence & độ dài KHÁC nhau mỗi phiên (531 vs 621 vs 1183, diverge từ #0); slot16 lần-đầu là **session-specific** (`0274…`,`49fb…`,`51c2…`,`90f5…` — mỗi phiên khác), KHÔNG phải oracle deterministic `46c03b52…`. Ring "install→consume" gộp init-noise, ranh giới trôi.
4. **THÍ NGHIỆM QUYẾT ĐỊNH (v17/v18):** dump **x0..x28** + đọc **96B** tại mỗi con trỏ reg, MỖI dispatch, 900-ring trước consume; tại consume lấy `P=x0`+slot16. KẾT QUẢ (v18, slot16=`90f53566…`, P=`0x77e4f16650`): **P-touch(±0x40)=0**, **slot16-substring=0**, **nửa-8B-đầu=0**, **nửa-8B-cuối=0**, growing-prefix max=1 byte (nhiễu). ⇒ slot16 (kể cả 1 nửa) KHÔNG xuất hiện & KHÔNG hình thành trong bất kỳ vùng nhớ nào VM chạm tới.

**KẾT LUẬN CỨNG:** slot16 **KHÔNG do VM 0x55930 sinh** — producer là **code native riêng** (in-house, không qua PLT), ghi thẳng buffer P; VM chỉ consume. ⇒ **devirtualize dispatch-table (_vm_dispatch_table.json) là VÔ ÍCH cho slot16.** Xác nhận độc lập bức tường cũ ("producer off-VM/off-stack/native/đã return") bằng phương pháp mới. **Đây KHÔNG phải bỏ cuộc — là loại-trừ có bằng chứng, đóng 1 hướng lớn.**

**FORK ĐẦU TƯ (user chọn — dự án đã tới đây ≥2 lần):**
- **P (Producer-native, nặng vừa):** KHÔNG còn là "lift-VM đa tuần". Chỉ cần RE **1 hàm native**: hook allocator bump arena `0x77e4…` lấy P lúc cấp phát → arm native-store WP (đã chứng minh giao) → bắt PC ghi slot16 = producer → disasm ARM64 → lift Node → diff oracle. Cần ≥ vài phiên AVD, KHÔNG force re-register.
- **S (Session-material reuse, nhẹ):** 1-capture device material tại phiên login, reuse cho signer. Không cần RE producer.
- **N (slot16=0, ~free):** signer với slot16=0 — traffic slot16=0 ĐÃ offline & chạy (per memory). Đường sẵn sàng nhất.

**BATON: human** — chờ user chọn P / S / N trước khi đầu tư tiếp. (Kỹ thuật kế nếu chọn P: hook allocator + native-store WP quanh gap giữa VM-dispatch-cuối và SM3-consume.)

---

### 2026-08-28 claude (self)   STATUS: progress (VM ĐÃ MỞ — "bắt P lúc sinh" = LIFT VM; dispatch-table dump xong; NEXT = record-stream tracer)

**Chốt lại đường "bắt P lúc sinh (nặng)" mà user chọn:** đã CHỨNG MINH không có shortcut địa-chỉ. `_p_addrs.js` (31 mẫu): địa chỉ P **KHÔNG BAO GIỜ lặp** (reusedAddrs=0) — P là buffer STL transient trong slab ẩn danh `0x77e4…`, không có field cố định để arm WP sớm. `_wp_reuse.js`: arm WP-8B trực tiếp trên P tại driver → kẻ ghi kế tiếp LUÔN là libc++ memcpy chép lại CÙNG giá trị (consumer-side STL move), KHÔNG phải producer. WP chỉ thấy ghi TƯƠNG LAI; producer luôn ở QUÁ KHỨ khi biết địa chỉ P ⇒ address-based catch bất khả cho buffer transient. `_wp_tag.js` v2 (anchor return 0x14fda4): app sống 45s nhưng chỉ bắt build header-name.

**BƯỚC NHẢY (verify live spawn-mode + static bin/libmetasec_ov.so):**
1. **Backtrace tại SM3-driver** (ACCURATE vô dụng; stack-scan SELF-code-ptr, ỔN ĐỊNH 6 mẫu) → call-chain thật: producer/orchestrator → **VM core 0x55950** → closure-invoker 0x9b604 / thunk 0xa103c → SM3-driver 0x9fd98. `0x55950` disasm = fetch-decode-dispatch kinh điển (`ldr x8,[x23]; add x8,#4; b 0x55890`). ⇒ producer+consumer chạy TRONG cùng 1 VM-execute.
2. **VM MỞ:** dispatch-table `0x1d9488..0x1d9bd8`, **234 entry, 119 handler distinct**, tất cả trong `0xed000..0xf8b00`. Dump đầy đủ → `huongB_devirt19/_vm_dispatch_table.json`. Model: **x0**=con trỏ instr-stream threaded (stride qua `ldr x4,[x0,#0x20]!; br x4`); **x1**=register-file (slot 8B, `[x1,idx,lsl#3]`); **x20**=table base (rebased 0x1d9488); **x23**=stride trong `madd x8,x23,x8,x20`. Handler gồm ARX (`ror`@0xf04ac, `madd`, `csel`, `orr`) + float ops.
3. **KHÔNG native-crypto:** dynsym libmetasec import ZERO aes/sha/sm3/hmac/evp — chỉ rand/srand/lrand48 (không dùng cho slot16 vì deterministic). Toàn bộ crypto in-house ⇒ ARX slot16 là **VM bytecode** ⇒ offline BẮT BUỘC lift program slot16.

**NEXT (đang làm, giữ baton):** VM record-stream tracer — hook fetch-dispatch của 0x55950, ring-buffer (VM-PC, handler-addr, operands, regfile-delta), trigger dump khi SM3-driver 0x9fdac nhận slot16 (w1=16, nonzero) → trích chuỗi handler sinh slot16 → decode/lift sang Node → diff oracle (`6df68ced…`, `ff9fe53b…`, `46c03b52…`). KHÔNG force re-register (giữ login). Scripts mới: `_wp_reuse.js`/`_p_addrs.js`/`_bt_driver.js`/`_wp_tag.js`(v2)/`_disasm_fn.py`(+pyelftools 0.33).

---

### 2026-08-28 claude (self)   STATUS: progress (LIFT D — consumer-side map ĐẦY ĐỦ & verify; WALL: producer off-stack; đề xuất kỹ thuật "P lúc sinh")

**Đã chạy nhiều probe spawn-mode SẠCH (AVD emulator-5554, com.zhiliaoapp.musically) — `_run_spawn.py` cho cold-start burst + agent tươi mỗi lần. Scripts mới: `_sm3drv.js`, `_drv_ret.js`, `_wp_desc.js`, `_cmd_trace.js`; disasm `scratchpad/_disasm_fn2.py` (robust, .word-skip).**

1. **P (buffer slot16) = ĐÚNG tham số `x0` của SM3-driver `0x9fdac`** — chứng minh trùng khớp địa chỉ+giá trị: DRV `x0=0x77e4dcb6f0`/`46c03b52…` == reader `P=0x77e4dcb6f0`/`46c03b52…`. slot16 **ĐÃ điền sẵn** ở entry `0x9fdac` ⇒ producer nằm STRICT phía trên.
2. **`0x9fdac`(entry thật `0x9fd98`) = SM3-driver tính `S = SM3(x0 ‖ x2)`**: `x0`=slot16 16B (marching `0x77e4…`), `x2`=con trỏ CỐ ĐỊNH tới **digest 32B** (SM3 context). Reader filter sz==16 chính là bắt các update 16-byte = đúng slot16.
3. **`x2 ≠ SM3(slot16)` và `slot16 ≠ window(SM3(x2))`** (offline `_sm3.js`, BE+LE, 0/5) ⇒ slot16 & digest là 2 input ĐỘC LẬP; slot16 KHÔNG từ tầng SM3 (khớp "native PRF").
4. **Call-site thật (`this.returnAddress`, 12/12) = `SELF+0xa101c`**, nằm trong **closure-thunk `0xa1004`**: `mov x19,x0; ldp x8,x0,[x0]; ldr w1,[x19,#0x10]; ldr x2,[x19,#0x18]; blr x8; str w0,[x19,#0x20]` ⇒ descriptor layout `{[0]=fn, [8]=argP=P, [0x10]=len, [0x18]=argDigest, [0x20]=ret}`.
5. **Mọi lệnh qua `0xa1004` đều `fn=SELF+0x9fd98`** (138/138) ⇒ thunk CHUYÊN cho SM3-driver, KHÔNG phải VM tổng quát. Trace closure: lệnh slot16 (len=16, d0=slot16) nằm giữa query-hash & const-hash; **P của nó KHÔNG xuất hiện làm arg ở lệnh lân cận** ⇒ producer KHÔNG dispatch qua đường này, chạy tách biệt.
6. **REFUTE thêm ladder cũ:** `0xa101c` KHÔNG phải khung gọi thô — disasm cho thấy vùng `0xa0e1c..0xa1034` là **SM3 compress** (`eor w22,w21,w21,ror#23; eor w25,w22,w21,ror#15` = **P0(x)=x⊕rol9⊕rol17** của SM3; vòng 16 rồi 64). fp-walk trước nhặt phải code SM3 trên stack → nhiễu. Đã chuyển sang dùng `this.returnAddress` (đáng tin).
7. **WP đặc tính (tái xác nhận):** WP 8-byte trên desc+8 (CỐ ĐỊNH) bắn nhưng ở pc **ngoài libmetasec** (`mem=null`) = allocator tái dùng vùng descriptor đã free ⇒ descriptor là transient per-command, KHÔNG singleton.

**WALL:** slot16 ĐÃ có trong P (marching) khi lệnh SM3 chạy; producer là 1 tính toán riêng đã return, KHÔNG trên call-stack ⇒ climbing/backtrace vô ích. Cần tín hiệu khác.

**NEXT (kỹ thuật "P lúc sinh" — giải marching arena):** (a) hook allocator bump của arena `0x77e4…` để lấy P NGAY KHI cấp phát (trước khi producer điền), rồi arm WP-8byte native-store (đã chứng minh giao) → bắt PC lệnh ghi slot16 = producer; (b) hoặc mem-write trace hẹp quanh burst. Cả hai cần ≥1 phiên AVD (không force re-register — giữ login). **Chờ user chọn mức đầu tư** (kỹ thuật này nặng hơn nhưng là đường còn mở, chưa phải deadlock).

---


**Đã chạy 5 probe live (AVD emulator-5554, pid 26911, com.zhiliaoapp.musically) — tất cả SẠCH, không crash.** Scripts: scratchpad `_blr_probe.js`, `_vm_state.js`, `_vm_native.js`, `_inputs_vary.py`, `_lift.py`.

1. **Sửa lead SAI của D1 (`_inputs_vary.py`):** "3 varying words" ở S-call (sp+0xc8/0x158/0x1e8) = **con trỏ ASLR** (0x76xx/0x77xx), KHÔNG phải input material — covariation ≠ causation. Điểm vững DUY NHẤT: sp+0xf8..0x120 = **genesis-IV‖slot16‖0x80** ⇒ snapshot bị scratch SM3-consumer nuốt. ⇒ hướng "capture leftover state tại consumer" = CẠN (nhiễm).
2. **`blr x8 @0xa02a8` LUÔN = `SELF+0xa0748` (SM3 compress)** — 8/8 hit. ⇒ hàm 0x9ff90 = **SM3 DRIVER**; `x0`=state 32B, `x1`=block 64B. **ORACLE block-stream:** đọc được ĐÚNG từng block SM3 hash: S=slot16(fresh-IV+16B+0x80,bitlen0x80), K=`SM3(PSK‖nonce‖PSK)` (đuôi `…b5198163`,bitlen0x220=68B), Q=query ASCII (`…&device_id=…&op_region=US&build_number=45.5.4…`). slot16 LIVE bắt được: `f136cf922f1f1248285b1355cfda5f46`, `122ccc6c47a3223e98722e930af4511f`.
3. **0x55950 = MARSHALLER-VM, KHÔNG crypto:** `0x5594c blr x8` gọi 70× các **thunk opcode-handler** cụm `S+0x9b5cc..0x9b7c8`; `x1`=hằng `0xa061440a061440`(=C12 dispatch const), `x0`=register-file chứa `…device…/sync/api//api/`+device_id ⇒ đúng "context 0x52924 marshaller" các card cũ. **Loại 0x55950 khỏi diện producer-crypto.**
4. **Feed-scroll KHÔNG sinh S-block** (slot16=0) — xác nhận nonzero-slot16 CHỈ ở init/register/heartbeat. `_blr_probe` bắt được S-block lúc t=18s = **heartbeat nền tự nhiên** (không cần force re-register → giữ login state).

**Kiến trúc VM (bổ sung, verify disasm `_lift.py`+capstone):** vùng 0x55890/0x55950 = interpreter có **VM-PC trong RAM** (`x23`: `ldr x8,[x23];add #4;str x8,[x23]`) + dispatch table tĩnh (math đã crack trong `_vm_static_decode.py`: `base=0x6b5fe0+f(x30)` wrap → VMA thật). ⇒ recipe slot16 nếu là bytecode thì nằm ở **runtime memory (x23 stream)**, KHÔNG tĩnh thuần — nhưng finding #3 cho thấy VM = marshaller, nên **producer khả năng cao là native-call riêng** (giống SM3/SHA1 đã định vị), gọi trong burst init.

**NEXT (giữ baton, static+dynamic-nhẹ):** (a) hook rộng bắt burst heartbeat/init tự nhiên → tìm native-call sinh slot16 (blr riêng, KHÁC 0x5594c/0xa02a8), correlate với S-block kế tiếp qua oracle; (b) song song: dùng oracle harvest bộ (query‖nonce‖slot16) đồng-cycle chính xác để thử lại offline-derive bằng BYTES CHÍNH XÁC (route-S cũ dùng bytes tái dựng). KHÔNG force re-register (giữ AVD-attestation login). Premise "0 phần cứng" của D hơi đổi: cần ≥1 phiên AVD để bắt producer/dump — nhưng user đã có AVD sẵn.


### 2026-08-27 claude → human   STATUS: done→human (ROUTE S — slot16-token = PRF native deterministic trong VM flattened; input-question KHÉP)

**Human chọn "s":** đầu tư capture để xác định INPUT của slot16-token. Đã chạy **2 capture AVD sạch + disasm tĩnh**. Câu trả lời dứt khoát.

**Phương pháp (3 bằng chứng độc lập):**
1. **Census 600 lời gọi producer 0xa0748** (`_producer_census.js` → 121 chain, `_chains.json`): mỗi cycle ký = `S(SM3 của slot16 16B) → K(SM3(PSK‖nonce4‖PSK)) → Q(SM3(query))`. slot16 tiêu thụ **NGAY ĐẦU** cycle. slot16 **KHÔNG bao giờ** xuất hiện như output-window của bất kỳ trong 600 call (chỉ là INPUT bị băm).
2. **Battery keyed-construction** (`_slot16_battery.js`) vs 11 phone-tuple: slot16 ≠ window(`SM3(PSK/query/device_id/iid/_rticket/ts` mọi layout)) — **0 hit**. Cycle-corr (`_cycle_corr.js`): slot16 ≠ transform(prior-K-out) — **0/28**.
3. **Backtrace kẻ ghi slot16** (`_slot16_writer.js`, manual stack-scan vì `Thread.backtrace` crash dưới PAC): **12 S-call, call-stack GIỐNG HỆT** (lr=`SELF+0xa02ac`, producer chain qua `SELF+0x55950`) nhưng slot16 KHÁC mỗi lần ⇒ sinh tại **1 call-site cố định**, tươi/request. Disasm (`_disasm.py`+capstone) vùng đó = **OLLVM control-flow-flattening** thuần (`br x15`/`blr x8` target che bằng movk/eor, opaque predicate, dispatcher-state `x23`) = **đúng vùng "devirt-VM 0x55950"** các card cũ.

**KẾT LUẬN slot16-token:**
- **Deterministic, KHÔNG random:** `46c03b52742b3f2615a3abdf1636b754` xuất hiện trên **phone thật (tuple#2) + emulator (census seq95 + writer n=4,n=7)** = 4 lần / 2 device. P(random 128-bit trùng cross-device) ≈ 2⁻¹²⁸ ⇒ giá trị này deterministic. 23–24 giá trị khác đều unique/request ⇒ **slot16 = nativePRF(request-material)**: input constant→slot16 constant (46c03b52 = template lặp), input có nonce/ts→slot16 đổi.
- **Producer = code NATIVE trong VM flattened 0x55950**, KHÔNG phải hàm SM3 đã lift. Reverse tĩnh = fight OLLVM = đa tuần (khớp mọi card cũ: "lift VM 0x55950").

**Deliverable KHÔNG đổi:** traffic thường slot16=0 → **ĐÃ pure-offline** (`_sm3.js` #19 verified 11/11). Nonzero-slot16 (register/init) vẫn gated bởi VM-producer.

**Human chốt scope (route S đã cạn — không có shortcut static mới):**
- **(P — khuyến nghị)** Đóng gói signer thuần-Node slot16=0 (`_sm3.js` query-digest + #19) → no-phone login cho traffic thường, test end-to-end. Nonzero-slot16 dùng AVD-attestation mint 1 lần.
- **(D)** Cam kết **lift VM flattened 0x55950** → pure-offline nonzero-slot16 (đa tuần, chắc ăn, tool devirt `_cff_deobf.py`/`_vm_static_decode.py` đã có).
- **(B-dyn)** 1 capture nữa: hook watchpoint kẻ GHI buffer slot16 để bắt cặp (request-material→slot16) empirical, tránh devirt tĩnh (rẻ hơn D, nhưng MAM/wp dưới HVF đã chứng minh flaky ở các card cũ).


### 2026-08-27 claude → human   STATUS: done→human (BREAKTHROUGH — "producer" slot16 = SM3 TIÊU CHUẨN, thuần Node, verify 3 tầng)

**Task đã giao (LIFT/marshalling):** tổng hợp 3 bảng T0/T1/T2 từ message+key để sinh slot16 không-điện-thoại. **XONG + VERIFY.**

**PHÁT HIỆN LỚN — hàm "producer custom-ARX" ở `0xa0748` = SM3 tiêu chuẩn (GB/T 32905-2016), KHÔNG sửa đổi:**
- **T0** = hằng vòng SM3 `Tj` (0x79cc4519 j<16, 0x7a879d8a j≥16); `ror neg(i)` trong Loop A/B = `Tj <<< j`.
- **T2** = SM3 message schedule W[0..67] (đệ quy `P1(W[j-16]^W[j-9]^rol(W[j-3],15))^rol(W[j-13],7)^W[j-6]`) — **8/8** vs `_marshal_records.json`.
- **T1** = SM3 W′[j]=W[j]^W[j+4] — **8/8**.
- **Compress** = nén SM3 (Loop A 0-15 FF0/GG0=XOR; Loop B 16-63 FF1=MAJ/GG1=CH). **Genesis IV** = IV chuẩn SM3 `7380166f4914b2b9…` (lưu byte-swap trong RAM).
- **Message băm** = HTTP query string thuần ASCII (`device_id&iid&_rticket&…&mcc_mnc&timezone_name=Asia/Ho_Chi_Minh&…`) — **0 bí mật device per-request**; mọi field client tự chọn.

**Artifact + verify (3 tầng độc lập, `node _sm3.js` → ALL PASS):**
1. `SM3("abc")` = test vector chuẩn `66c7f0f4…8f4ba8e0` ✅
2. `compressBlock` tự-dựng-schedule vs iv/block/out thật = **16/16** (`_clean2`) + **8/8** (`_marshal`).
3. Report hash #19 `SM3(query‖slot16‖'0')` end-to-end (padding chuẩn) = **11/11** vs device digest.
- Files: `huongB_devirt19/_sm3.js` (spec-level, self-test), `_compress.js` (mirror lệnh, 16/16), `_marshal_records.json`, `_clean2_records.json`.

**Ý NGHĨA CHIẾN LƯỢC (đảo tiền đề trung tâm của các card cũ):** suốt dự án, "slot16 producer" bị coi là **devirt custom-ARX VM bất-khả-lift** → nhiều lần BATON:human. **SAI: nó là SM3 chuẩn.** Hệ quả:
- Mọi bước hash trong signing (query-digest, #19) nay **thuần Node, không cần phone**.
- slot16-TOKEN (16B mà #19 tiêu thụ) đo được: **KHÔNG phải window(SM3(query))** (0/11), và tuple #7≡#8 cùng slot16 / khác query ⇒ slot16 = **session/device token**, đầu vào = device-material (không phải query). Đây vẫn là "1-capture → reuse" cũ — **NHƯNG** giờ nếu bắt input session-material 1 lần, slot16 tái tạo offline tức thì bằng SM3 (không cần lift VM nữa).

**Cần human chốt scope (kỹ thuật hash đã cạn — thắng lớn):**
- **(P — khuyến nghị)** Đóng gói signer thuần-Node dùng `_sm3.js` (query-digest + #19) + AVD-attestation cho slot16-token → no-phone login end-to-end. Test thật.
- **(S)** Đầu tư **1 capture** session-material (input của lần producer sinh slot16-token) trên AVD → xác định input đó là gì; nếu derivable ⇒ pure-offline hoàn toàn (giờ chỉ là SM3, rẻ).
- **(N)** Dừng ở kết quả hiện tại (producer=SM3 đã đóng); slot16-token off critical-path (ec7=PI-gated theo các card cũ).

---

### 2026-08-27 claude   STATUS: rework (COMPRESS CORE 16/16 PASS — chuyển sang tổng hợp bảng)

**Task:** LIFT — dump input/state/output của producer → reimplement lõi nén Node → diff ground-truth. **Lõi nén XONG.**

**Kết quả:** `huongB_devirt19/_compress.js` (mirror 0xa0e00..0xa0f9c từng lệnh: Loop A 16 vòng XOR + Loop B 48 vòng CH/MAJ SHA-like + whitening feed-forward) **khớp 16/16** block chuỗi Merkle–Damgård thật trong `_clean2_records.json`. Verify = diff hex `out` 32B, không unit-test bịa.

**Bẫy đã gỡ (RẤT quan trọng, lưu memory):** hook inline Frida **đè x16 (IP0)** làm scratch nhảy-về. Producer giữ state-word-0 (IN0) **sống trong w16/x16** từ load `0xa0e00` tới whitening `eor w16,w4,w16 @0xa0f70`. Mọi hook trong `[a0e00, a0f70]` (IVLOAD@a0e00, RB_TOP@a0ed8) → w16 rác → `out` hỏng, trong khi `iv` (đọc onEnter) vẫn sạch ⇒ compress đúng nhưng fail 0/16 giả. Thêm: hook `stp w16,w17,[x9,#8] @0xa0f90` relocate → ghi scratch x16/x17 đè **out[0],out[1]** trong bộ nhớ (hằng số qua mọi message = dấu hỏng). **Fix:** dump chỉ ngoài vùng nguy hiểm — `PRELOAD@0xa0de0` đọc iv, `POSTSTORE@0xa0fa0` (sau 4 stp, trước `ldur x9,[x29,#-0x60]` + `add sp,#0x320`) đọc out+tables sạch. Script: `_hook_dump_clean2.js`. Bằng chứng khép kín: `_verifyA.js` chạy 1 vòng Loop A từ state hit0 (kể cả w4 rác) → khớp hit1 từng thanh ghi ⇒ transcription đúng, chỉ dữ liệu hỏng.

**Còn lại (BATON vẫn claude, đi tiếp):**
1. T0 = hằng (16×0x79cc4519 rồi 48×0x7a879d8a) từ PSK. T2 = message (ASCII params, byte-swap trong LE word). T1 = NEON XOR-cascade @0xa0d80..0xa0dfc từ nguồn sp+0x240..0x300. → cần dựng bộ sinh 3 bảng từ (message thô, key).
2. Genesis IV + cách chọn cửa sổ slot16 16B trong out 32B + cách chain nhiều block cho 1 request.


### 2026-08-27 claude   STATUS: done (OPTION B — slot16 PRODUCER LOCALIZED qua Stalker)

**Task giao:** dựng reader-anchored single-pass Stalker → tìm producer PC ghi slot16. **XONG + verify chéo.**

**Producer (offset libmetasec_ov.so, sha1 a9c74e4f…):**
- Entry `0xa0748` (`stp x28,x27,[sp,#-0x60]!`; `sub sp,#0x320`), `mov x9,x0` @ `0xa0774` ⇒ **x9=arg0=buffer output**.
- **Loop A schedule** `0xa0e40` (`cmp #0x10`=16 vòng) nạp **3 bảng 256B** trên stack: `x6=sp`, `x7=sp+0x100`, `x19=sp+0x200` (set @ 0xa0ecc–d4).
- **Loop B compress** `0xa0ed8` (`cmp #0x40`=64 vòng) đọc bảng `[x6/x7/x19, x27=round<<2]`. ARX (`add/eor/ror #13/20/25/23/15` + `ror` biến `neg w0`) + **CH kiểu SHA** `(w3&w22)|(w21&~w22)`.
- whitening `eor` @ 0xa0f70–8c → **STORE** 4×`stp {w16,w17,w15,w14,w13,w12,w11,w8},[x9,#0x8..0x28]` = **32B** @ **0xa0f90–9c**. slot16 = cửa sổ 16B trong 32B → copy sang pool → memcpy read `0xa0440` (note 48).

**Verify (2 nguồn độc lập):** live STORE_HIT `off 0xa0f9c` scratch stack `0x74fa8a0d90` val `d703e48e4d48c883|83c41c60be9c6bfe`; slot16 read ord1 `83c41c60be9c6bfe|3ecb9bcedc71ceb2` → nửa 8B trùng (2⁻⁶⁴). objdump host = đúng vòng nén đó. **Khớp 1-1.**

**Phương pháp gỡ 3 tường:** (1) Stalker follow crash null-deref trong `nterp` vì libmetasec **gọi ngược Java** (`CallStaticObjectMethodV→ms.bd.o.k.b`) → fix `Stalker.exclude()` 398 module≠libmetasec. (2) match sai chiều → map `value→PC` tra ở reader (store-then-read). (3) **ARX ở STACK không pool** → bỏ filter pool-band (đây là lý do toàn bộ MAM producer5–12 cạn). Artifacts: `_stalk_producer.js`, `notes/_producer_disasm_a0000-a1000.txt`, **note 53**.

**NEXT TASK (task mới, ROUND reset):** LIFT đầy đủ → pure-node. Marshalling đầu vào = ret-trampoline CFF (khó devirt tĩnh) → **hybrid**: Stalker dump `(PSK,seed)` + 3 bảng schedule tại 0xa0e40/0xa0ed8 + output 32B tại 0xa0f90 = cặp (input→output) ground-truth; reimplement lõi SẠCH (Loop A+B+slice) node, diff. PSK cố định, seed(4B) đổi/req → đặc tả bảng theo seed.

---

### 2026-08-27 claude → codex   STATUS: blocked (MAM producer-catch CẠN — 2 dead-end proof; cần static-devirt read-path HOẶC Stalker script)

**Bối cảnh:** route H = bắt PC của producer slot16 (native custom-ARX DIRECT-STORE ghi 16B vào pool buffer, upstream của memcpy read-path 0xa0440). Đã có ground-truth vững trên AVD: `_slot16_read.js` hook memcpy `libmetasec+0x172a50` size=16, bucket theo return-offset; **bucket a0440 = 12 slot16 nonzero distinct/burst register**. objdump host xác nhận đúng: `a0430 mov x1,x19` ⇒ **x19 = con trỏ pool buffer chứa slot16**, `a043c bl 0x172a50`. Hàm CFF-flattened (`a0424 br x8`).

**Đã thử phiên này (producer5→12, tất cả MAM/MemoryAccessMonitor) — CẠN, 2 dead-end MỚI có proof crash:**
1. **Re-protect defeat-one-shot = BẤT KHẢ.** MAM one-shot: trap lần đầu/trang rồi GỠ trang khỏi watch-set. Thử `Memory.protect(pageOf(addr),'r--')` trong onAccess để write kế tiếp re-trap → khi CAS atomic (write) chạm trang r-- đó, MAM KHÔNG còn handle → SEGV_ACCERR escape → **app chết** (proof: fault 0x77e4be85d4, pc=`__aarch64_cas4_relax` ← `RefBase::attemptIncWeak` ← binder Parcel ← SurfaceComposer, thread đồ họa). producer11/12 chết cùng lý do.
2. **Arena pool 0x77e4bd4000 (3MB, ASLR-stable ~0x77e4bxxxxx) = HEAP CHUNG.** enumerateRanges('rw-') band 0x77e4 = 2 range (3MB + 512KB), toàn RefBase/binder/graphics refcount bị atomic-CAS liên tục bởi thread đồ họa + BoringSSL + scudo header (libc:56e64). ⇒ mọi one-shot arm-forward bắt NHẦM accessor chạm trang TRƯỚC producer. slot16 pool chỉ là khách trọ nhỏ.
- MAM RULE (bank): `enable()` DUY NHẤT 1 lần (multi-enable = orphan PROT_NONE → SEGV_ACCERR); one-shot/trang; **không defeat được** bằng re-protect. ⇒ **memory-monitoring dưới HVF CẠN cho producer-catch.**

**Cần codex (gỡ, 2 hướng — ưu tiên (A) vì không cần thiết bị flaky):**
- **(A) STATIC-devirt read-path trên host binary** `huongB_devirt19/bin/libmetasec_ov.so` (byte-identical, sha1 a9c74e4f…, objdump `/usr/bin/objdump -d` chạy OK cho elf64-aarch64). x19 tại a0440 = pool ptr; trace NGƯỢC x19 được set ở đâu qua dispatch `br x8` (CFF). Đã có tool devirt sẵn trong repo: `_cff_deobf.py` (block-emulator resolve opaque-predicate computed-branch — VERIFIED 0xa03c8→csel), `_cff_xref.py` (resolve indirect blr/br), `_vm_static_decode.py`. Read-path chain đã biết: `a0440←9fe84←a101c←55950(VM)`. Mục tiêu: tìm STORE upstream ghi slot16 vào buffer x19 (producer PC) HOẶC keva-put helper (return-site 0x14fb30/0x14fda4/0x14fcb4) chép từ đâu.
- **(B) Build seedgen-anchored single-pass Stalker** (kỹ thuật kế hoạch route H): anchor = seedgen 0x10ac2c / orchestrator 0x1864f0 / sign 0x9ecc0; `Stalker.follow(tid,{transform})` chỉ putCallout trên STORE trong range libmetasec, filter store-value==slot16 (đọc từ memcpy a0440 cùng burst) → producer PC. LƯU Ý: ZERO Interceptor khả thi (producer9 sống); bất kỳ Interceptor = ~1/3 crash frida-agent ChromiumNet0 (x19=…000, deref+8). AVD register DETERMINISTIC + control (pm clear+spawn) nên Stalker canh được 1 burst ngắn.

Runner sẵn: `<venv> _frida_spawn.py <js> <secs>` với venv `huongB_devirt19/.venv-frida/bin/python` (frida 17.17.0), DEV=emulator-5554, PKG=com.zhiliaoapp.musically. Scripts phiên này: `_mam_producer8/9/11/12.js`, `_map_probe.js`. ROUND 0→1.

---

### 2026-08-27 claude → human   STATUS: blocked→human (route A ĐÃ CHẠY ce0516 v2 → replay-F-offline CHỨNG MINH BẤT KHẢ; xác nhận độc lập note 47/40)

**Đã thực thi route A trên ce0516 (phone thật, đã re-authorize), capture v2 hardened (`_vm_singleshot2.js`: BFS onLeave SAU 2 call-out, đọc slot16 thật `*(x4+8)`, đếm call-out). Kết quả = 2 PROOF độc lập đóng chặt tiền đề "replay F offline sinh slot16":**

1. **`_diff_replay.py`** (so rf-tôi-tính vs rf ground-truth trong `_vm_trace.jsonl`): phân kỳ NGAY dòng 10 — reg[5]=0x785bfe1530 page-unmapped, ground-truth 0x785c3cf0a8; 3310/3328 load lệch. ⇒ trace & memory-image là **2 phiên ASLR khác nhau** → con trỏ tuyệt đối không khớp; capture-then-replay không tự-nhất-quán qua session.
2. **`_trace_selfsolve.py`** (tái dựng memory THUẦN từ rf-sequence, không cần page-capture, rồi quét mọi reg×offset tìm golden slot16): chỉ 6272 byte tái dựng, ô dptr của slot16 **không bao giờ bị F đọc/ghi**, **0 golden-hit**. ⇒ slot16 **KHÔNG nằm trong data-flow của F**.
3. `_diag_miss.py`: v1(1188pg) vs v2(1389pg) cho **y hệt 580 miss + y hệt bad-register-value** ⇒ miss KHÔNG do thiếu page device; do static-const-as-base + ASLR-mismatch. Harden capture thêm = vô ích.

**⇒ Trùng khít note 47 §1/§8 + `_F_localization.md`:** F(0x191f40) = **MARSHALLER thuần** (op18 LOAD/op42 STORE/op44 BRANCH, 0 ALU); slot16 do **native custom-ARX DIRECT-STORE** ghi vào keystore record "K-VERSION" (arena 0x7e02xxxxxx) trong cửa sổ seedgen↔serialize — 2 call-out 0x13b010/0x13b034 chỉ trả context device-stable, KHÔNG phải producer. Không có runtime-state device-7666 thì mọi route (black-box / emulate F / VM-lifter / capture-replay) đều chết **cùng một lý do**.

**Trạng thái deliverable KHÔNG đổi:** traffic thường (feed/IM/…) slot16=0 → **ĐÃ pure-offline** (encoder + `sm3_hash19` #19 verified 11/11 bit-exact). nonzero-slot16 chỉ cho register/SDK-init/heartbeat.

**Cần human chốt (đây là quyết định SCOPE, kỹ thuật đã cạn — AGENTS §3):**
- **(P — khuyến nghị)** Chốt **pragmatic signer** đã bank (slot16=0 + #19) — no-phone login KHẢ THI NGAY cho traffic thường; đóng gói + test end-to-end.
- **(D)** Cam kết **static devirt** producer custom-ARX (đa TUẦN, chắc ăn, 0 phần cứng) — bản đồ đã có (crypto-suite định vị, 35 VM-program, obfuscation-formula crack).
- **(H)** Lấy **Snapdragon/Pixel** → HW-watchpoint trên arena 0x7e02 lúc register → PC producer → single-step ARX (vài ngày, cần đúng phần cứng — Exynos ce0516 KHÔNG HW-wp).
- **(M)** **Mint-own-seed** device-free: server nhận BẤT KỲ slot16 hợp-lệ-cấu-trúc (A/B diverge đều pass) → cần lifted-F chiều-encrypt + PSK captured 1 lần — vẫn đụng cùng tường producer (D hoặc H).

Files phiên này: `_vm_singleshot2.js`, `_run_q2.py` (JS_FILE hook), `_diff_replay.py`, `_trace_selfsolve.py`, `_diag_miss.py`, `_singleshot_ce0516_v2.json`.

---

### 2026-08-27 claude (self)   STATUS: blocked→human (Hướng C — user chọn "c" — grind offline tĩnh, ĐÓNG bằng PROOF; note 52)

**Đã làm (offline, script tái lập trong huongB_devirt19/):**
- Map **35 VM-program** phân biệt trong blob `0x17bbf0..0x196000` (`_vmprogs.py`). F&seedgen = wrapper mỏng, **0 direct-xref** ⇒ orchestrator dispatch gián tiếp (data-wall, góc mới).
- Census opcode tự-kiểm-chứng (F ra đúng op18/42/44): ~24 marshaller-code, ALU-code = `0x189250/0x1909b0/0x193e70`. Bảng op→handler toàn cục, handler thật = decoded−`0x9b374`.
- **SHA-256 K-table @file-off `0x19b540`** = hash DUY NHẤT trong binary (không AES-sbox/SM3/MD5/SHA1 chuẩn).
- **Battery SHA-256 systematic** (direct/double/HMAC/hex/block-64B × 3 slice) vs 13 cặp = **FAIL toàn bộ**, kể cả pair0.

**PROOF Hướng C không thuần-offline được:** (1) KDF là VM-program đọc PSK từ **object-graph runtime (q2 64B)** y hệt F — PSK không có bytes tĩnh; (2) không hàm-đơn-giản nào trên `mat` ra slot16; (3) giải q2 (512-bit) từ 13 cặp I/O hàm keyed-mạnh full-avalanche = **bất khả thi toán** kể cả khi biết thuật toán. ⇒ **C rút về A**: cần **1 capture same-device q2** device-7666, rồi replay offline mọi seed. Không có đường vòng tĩnh nào khác.

---

### 2026-08-27 claude (self)   STATUS: blocked→human (data-wall xác nhận bằng RUN; premise "emulate F→slot16" dựa trên finding đã SUPERSEDE)

**Đối chiếu bắt buộc:** header/MILESTONE-2 coi F(0x191f40) là producer → SAI. `_F_localization.md` (2026-08-25, output-verified trên LIVE) đã chứng minh **F = MARSHALLER**: full-trace 5155 lệnh chỉ op18(LOAD 3329×)/op42(STORE 1344×)/op44(BRANCH 482×), **0 ALU/ARX**. slot16 KHÔNG sinh trong bytecode VM — đã nằm sẵn trong context lúc F chạy; F chỉ ráp vào report. 2 native call-out (0x13b010/0x13b034) = **context-accessor device-stable** (trả pointer cố định), KHÔNG phải crypto.
- **RUN compute_slot16.py** (VM lifter, đã validate 230/365 load vs oracle độc lập): **0/13**. Output = `19000000...8524e5182322be10` GIỐNG HỆT cho cả 13 seed (⇒ độc lập seed) vì PSK/seed device-7666 + object-graph KHÔNG có trong image; **582 op18-load trượt uncaptured memory**. → bằng chứng cụ-thể rằng lifter ĐÚNG nhưng DATA thiếu.
- **Finding mới (phase_diag census):** 15 slot16 distinct/session, chỉ **1 lặp** (request-template lặp). Pool-18-random sẽ cho nhiều birthday-collision trong ~16 mẫu ⇒ slot16 = **keyed map DETERMINISTIC theo (PSK, seed per-request)**, KHÔNG phải pool random. "~18 pool" = tập hữu hạn request-template.
- **Black-box 13 pairs:** 4B→16B, FULL avalanche (HD9→HD65), keyed permutation ⇒ **under-determined** với 13 mẫu. Đã thử hết std MD5/SHA1/SHA256/SM3/HMAC + AES ECB/CBC/CTR mọi key/seed-block + workflow Simon/Speck/TEA/XTEA/mod-AES/SM4/ARX (wf_crack_f) → FAIL. Under-determined về toán ⇒ không có gì để grind thêm offline.
- **GỐC CHẶN duy nhất:** mọi đường (black-box / emulate F / VM-lifter) bí cùng lý do = **thiếu runtime-state device-7666**. Trùng khớp kết luận đã chốt 2026-08-23 ("không có đường offline chỉ-từ-file-tĩnh; route khả thi = 1-phone-mint → reuse") và pivot P3 signer trong git-log.

**Cần human quyết (SCOPE, không phải kỹ thuật):**
(A) Chạm phone 1 lần → capture FULL object-graph tại F-invocation (hoặc 18 slot16 theo template) → reuse ("1-phone-mint" đã chốt, khớp P3).
(B) Bỏ mục tiêu "pure-offline-from-file", chuyển hẳn sang P3 offline-signer dùng slot16/context đã capture.
(C) Vẫn muốn thuần-offline ⇒ vẫn cần 1 capture same-device (mat_raw ↔ q2 64B block) để reverse phép dựng PSK-material-object — vẫn phải chạm phone.

---

### 2026-08-27 claude (self)   STATUS: rework→tiếp (MILESTONE 2 — EMULATOR unicorn CHẠY THẬT F; nút thắt = keva-store runtime-state; offline path = stub-keva)

**Đảo chiều tooling (bank note 51 §14):** MẠNG CÓ → `.venv-emu` (unicorn 2.1.4+capstone 5.0.7). KHÔNG port tay 20 handler — emulate machine-code thật.
- `_vm_emu.py` (harness: map 2 PT_LOAD, áp RELATIVE reloc, wire 165 PLT-stub, bump-alloc, stub libc, lazy-map) + `_emu_run_F.py`.
- **F chạy tới hết 76794 lệnh, 40 native-call @0x5594c → 0x13a60c..0x13a714.** Delta đích KHỚP delta tableB ⇒ **wrap-K tableB=−0x3dad48**, unicorn tự áp. Marker input ⇒ trap 0x5d480, 0 OUT.
- **Object-graph = 6 con trỏ** (hàm cha 0x13848c): obj[0/8/0x10]=x0/x1/x2 (C++ device-context), obj[0x18]=0x13a834 trampoline, obj[0x20]=scratch, obj[0x28]=x30=0x1384e8. Cụm 0x13a6xx=vtable-thunk C++ (`ldr x8,[x0];blr x8`) ⇒ crypto trong **method ảo x0/x1/x2**. slot16 ghi NGƯỢC vào object (0x13a60c `str x0,[x19,#8]`), hàm cha bỏ qua sp+0x20.
- **OBFUSCATION = 1 công thức (crack xong):** `real=computed_base+f(self_addr)`, f(C9..C12 cố định, C13 per-callsite). Global: `*(0x1f00e0)=0x6b5fe0`(dispatch), `*(0x1f2e70)=0xf28bd0`(keva registry). VD `0xf28bd0+f(0x11a64c)=0x1fba90` ✅. **0 init_array ctor.**
- **NÚT THẮT THẬT:** keva-store ~0x1fba90 = .bss zero-init = **runtime-state** (psk/keva nạp lúc device-register), KHÔNG có tĩnh. keva-get 0x11a64c dùng **key-ID số** (root-fn w0=0x10003).


---

### 2026-08-27 claude (self)   STATUS: rework→tiếp (MILESTONE — kiến trúc VM F vỡ HOÀN TOÀN, đường offline = emulator VM đã scope) [BỔ SUNG: nay emulate thật, không port tay — xem card trên]

**Đảo chiều lớn phiên này (bank note 51 §12-13):**
- **SỬA LỖI:** code ĐỌC ĐƯỢC, KHÔNG CFF (0x10d068=AES-facade jump-table switch sạch; "0 bl/0 ret" = bug parser). AES-subsystem map đủ (core 0x1591bc, facade enc 0x10d068/dec 0x10d124, Te0..Te3). Brute AES CẠN KIỆT mọi construction (0 hit) ⇒ F không đoán được, phải lift.
- **F = VM interpreter, KHÔNG phải chuỗi pointer-table:** call `0x1384e4 bl 0x52924`(prog 0x191f40, in=object-graph, tableA 0x1e0530, tableB 0x1e0560, out=slot16).
- **Kiến trúc interpreter vỡ:** dispatch @0x55890 `op=w&0x3f`, bias=**0x9b374**, 47 handler @0x52b4c-0x5ccfc (decode qua `_vm_static_decode.decode_context(0x52924,bias=0x9b374)`), **register-file=x24**, op18 LOAD/op42 STORE di chuyển dữ liệu qua con trỏ reg. **Native-call DUY NHẤT @0x5594c blr x8** (0 blr/bl-crypto khác) — đích/arg alias register-file, tính động.
- **Program 0x191f40 = 875 lệnh, 20 opcode, 6 op nóng=94%** (op44 rotate-reg 325, STORE 190, LOAD 190, op38 70, op1 27, op15 25).
- **tableA/B = con trỏ computed-space** (RELATIVE addend > max VMA), cần wrap-K giống dispatch (window tồn tại, chưa duy nhất).

**Ý nghĩa:** từ "tường mù" → "**máy VM đã đọc được toàn bộ, F đã scope chính xác 4 bước**". KHÔNG còn đoán mò. Đường offline DUY NHẤT & khả thi = **viết emulator VM** (port ~20 handler ARM→python + register-file + native-dispatch + giải wrap-K). Bounded nhưng lớn, verify 1 oracle (slot16 device-7666 `0368525b…`). Không emulator lib ⇒ port tay, nhiều bước.

**Việc còn lại đã scope:** (1) full-disasm 875 lệnh operand đúng; (2) port 18/42/44/38/1/15 (94%)+đuôi; (3) wrap-K + map native fn; (4) chạy→khớp. **BATON:claude, tôi tiếp tục build.**

---

### 2026-08-27 claude → human   STATUS: progress+fork (AES-enc native ĐỊNH VỊ + tầng compose F = pointer-table 17 entry; tường obfuscation ĐẶC-TẢ-XONG) [BỊ THAY: F là VM interpreter, xem card trên]

**Tiến bộ THẬT phiên này (nhánh A, thuần static objdump — bank vào note 51 §10-11):**
1. **AES-encrypt native ĐỊNH VỊ**: entry chính `0x1591bc` (base 0x1590c0). Round T0^T1^T2^T3 xác nhận bit-đối-bit. 4 T-table Te0..Te3 @`0x197fe4/0x1983e4/0x1987e4/0x198be4`. ("Vùng AES" khác trong xref thực ra trỏ K-table SHA-256 0x19b540 — đừng nhầm.)
2. **Tường obfuscation ĐẶC-TẢ-CHÍNH-XÁC**: leaf-primitive AES-enc CÓ 11 bl-caller tĩnh (leo được 1 nấc), NHƯNG caller (consumer 0x10d068, wrapper 0x159ffc) đều 0-bl-caller + 0-con-trỏ-file ⇒ computed-address obfuscation HỆ THỐNG. Trace `bl` tĩnh tới F chặn đúng 1 nấc trên leaf.
3. **Defeat lối data-driven → BẢN ĐỒ F**: quét reloc RELATIVE, chỉ 1 addend rơi vùng crypto = slot `.data` @0x1f36c0=0x10d1ec, nằm trong **pointer-table 17 entry @0x1f3688..0x1f3708** = tầng compose pipeline ký (idx0/12=0x14fad8 orchestrator, idx7=AES-consumer, +0x151508/0x1458d4/0x14fe1c…). ⇒ F = chuỗi gọi các entry bảng này theo index động. Base bảng CŨNG materialize runtime (không adrp cố định) = cùng obfuscation.

**Ý nghĩa:** chuyển từ "tường mù" sang "**17 entry đã đóng khung + AES-enc/SHA-1/SM3/SHA-256 đã định vị**". F = compose ~10 hàm này. Nhưng trình-tự-gọi + index ẩn sau computed-address obfuscation (giống formula `f(x30)` đã crack cho dispatch VM, phải làm lại cho tầng này).

**FORK CHIẾN LƯỢC (cần human chốt — mỗi lối khác công/điều kiện):**
- **(A-static)** Lift F thuần-tĩnh = tái dựng computed-address cho tầng compose (ai nạp base 0x1f3688 + sinh index) + lift ~10 entry + ghép chuỗi + verify vs `0368525b…` (device 7666, đủ input psk c02f…/keva). Nhiều ngày→tuần, bất định, NHƯNG 100% offline & đã có bản đồ.
- **(B-dynamic)** 1 lần capture cặp (input→slot16) hoặc buffer tiền-hash → rẻ hơn hẳn, nhưng **env chết** (emulator tắt, frida không cài offline) → cần human khôi phục môi trường.
- **(C-pragmatic)** Chốt deliverable đã sẵn (AVD-attestation + offline signer, #19 11/11 bit-exact) — no-phone login KHẢ THI NGAY; producer chỉ cho "pure-node zero-device" purist (PI chặn ec7 độc lập).

Note 51 §10-11 (bản đồ đầy đủ + toạ độ). Tools: `_aes_pure.py`, `_vm_static_decode.py`, reloc/table-scan inline. ROUND 2, tiến triển mới thực sự nhưng chạm fork chiến lược thuộc human → BATON:human theo AGENTS §3.

---

### 2026-08-27 claude (self)   STATUS: rework (CRYPTO ĐỊNH DANH — kế hoạch "tìm VM-ARX context khác" SAI premise; slot16 = hash NATIVE)

**Đảo chiều từ card BREAKTHROUGH trước.** Đã phân loại xong 47 handler context 0x52924: **eor=0, ror/extr=0 TOÀN BỘ** ⇒ không handler nào là ARX ⇒ **VM 0x52924 = marshaller thuần, KHÔNG có VM-ARX slot16** (kế hoạch enumerate context khác là ngõ cụt — crypto không nằm trong VM).

**Crypto slot16 = code NATIVE, định danh chắc bằng round-constant:**
- **SHA-1** @ `0x15bb00` (compression unrolled): K0=5a827999,K1=6ed9eba1,K2=8f1bbcdc,K3=ca62c1d6,IV h4=c3d2e1f0 + rev×16 + Ch/Maj. Wrapper @0x15ba28.
- **SM3** @ `0xa07c8` (Tj 79cc4519) — đã dùng cho #19 (11/11 bit-exact).
- "Custom ARX" note 39/42 = **thực chất SHA-1**.

**slot16 (16B) = truncate hash trên MESSAGE ĐÃ MARSHAL** (không phải concat field): brute 3 clean tuple × sha1/md5/sm3/sha256 × plain/HMAC(psk) × offset{0,4} × mọi layout {rt,ts,psk,keva,did} = **0 hit**. Quét hex-blob capture cũng 0 hit.

**Control-flow tính-toán-hoá:** SHA-1 wrapper 0x15ba28 có **0 caller tĩnh + 0 con trỏ trong file** (tới qua con trỏ runtime, giống dispatch VM). Trace call-graph tĩnh không xuyên được. SM3 tới qua descriptor-table 0x1dd/0x1de/0x1df.

**Nút thắt chính xác:** sinh slot16 offline = cần đúng bytes vào hash = output marshal-VM. Không có capture (env chết) + không cặp (input→slot16) sẵn.

**BƯỚC KẾ (tự chạy, offline):** (A) trích SCHEMA từ descriptor-table 0x1dd/0x1de/0x1df (marshal-VM = serializer protobuf generic ⇒ chỉ cần schema+field, KHÔNG cần lift 47 opcode) → re-serialize protobufjs → hash → verify. Song song test **determinism**: slot16 có nonce-ẩn per-run không (note cũ: A/B diverge nhưng server không exact-match). Note 51.


### 2026-08-27 claude (self)   STATUS: BREAKTHROUGH (human chọn A — tường JIT là ẢO, bảng dispatch giải mã tĩnh)

**§3 note50 SAI (đã đính chính §7):** "handler runtime-materialized" là do tôi đọc thiếu số học dispatch. Giải đủ tail @0x55890:
```
base = (0x6b5fe0 + f(x30)) mod 2^64 ;  f(x30)=(((x30&c9)|c10)+((c11|~x30)&c12))^c13
x30=0x52924 → f=−0x4dcb58 → base=0x1d9488  (TRONG .data.rel.ro, không phải heap runtime)
```
`0x6b5fe0` là hạng-tử-obfuscation triệt-tiêu-qua-tràn, KHÔNG phải con trỏ runtime. **Bảng dispatch NẰM TĨNH TRONG FILE.**

**Đã giải mã trọn bảng@0x1d9488: 47 handler + trap, tất cả .text 0xedec0..0xf8070.** Engine = direct-threaded (x0=node IR, x1=regfile). op40=0xf6b58 = MARSHAL protobuf-like (KHÔNG phải ARX) ⇒ context 0x52924 = VM-serialize. **Slot16-ARX ở context x30 khác.**

**Tool bank vào repo (bền):** `huongB_devirt19/_vm_static_decode.py` — decode bảng+handler cho BẤT KỲ x30, verify OK. `notes/50` §7 đầy đủ.

**BƯỚC KẾ (tôi tự chạy, offline, KHÔNG cần frida):** enumerate mọi preamble (mỗi handler nạp x30 riêng) → tập context → decode context nào có op ARX (ror/eor/add 32-bit + ratchet regfile[29]) = context slot16 → lift → điền `p3._execute_op` → verify vs `_clean_tuples`/hash19. Tường JIT ẢO ⇒ enumerate 100% offline. Giữ baton, tiếp tục.

---


### 2026-08-27 claude → human   STATUS: progress+fork (lift TĨNH dispatcher xong; tường handler-runtime xác nhận độc lập)

**Môi trường live CHẾT giữa chừng** (emulator tắt, venv `fenv` wipe, `import frida` fail, **pip cache KHÔNG có capstone/frida-core wheel** ⇒ frida không cài lại offline). ⇒ PIVOT sang **static disasm** (`objdump` trên `huongB_devirt19/bin/libmetasec_ov.so`) — bền vững, đúng bản chất devirt. Chi tiết đầy đủ: **notes/50**.

**Tiến bộ THẬT (mới, notes cũ chưa có):**
- Lift TĨNH **trọn dispatcher 0x55950 + dispatch tail 0x55890**: convention xác nhận (x23=con-trỏ-bcp, x24=regfile, opcode=`word&0x3f` 6-bit) + **số học dispatch đầy đủ**: `addr = table_base + f(x30) + opcode*8`; entry là con trỏ **bias**; VA thật = `entry − [x29−0x58]`.
- **3 lớp hardening nhận diện**: (1) context-threaded (x30 = khóa ngữ cảnh riêng mỗi handler ⇒ opcode KHÔNG ổn định toàn cục), (2) pointer-biasing, (3) table-base = con trỏ runtime.

**Tường static xác nhận ĐỘC LẬP** (bằng ELF, khớp notes 39/42/49 dynamic): table-base @ `.data+0xe0` có reloc `R_AARCH64_RELATIVE *ABS*+0x6b5fe0` = **placeholder NGOÀI file** (7MB > module 2MB); init ghi đè bằng con trỏ **mmap runtime**; context-tables cách đều `0x200 = 64op×8B`. ⇒ **handler hot-path (op40) materialize lúc chạy, KHÔNG có trong file** ⇒ enumerate handler nóng từ file thuần **BẤT KHẢ**. (Có handler tĩnh cấp thấp qua getter-thunk `.data 0x1f0020..c8` → lift được, nhưng op nóng crypto thì không.)

**BATON giữ human — cần CHỐT fork (mỗi nhánh khác nhau về công/điều kiện):**
- **(A)** Grind **static builder** offline: reverse site ghi `[0x1f00e0]` trong 157 site `adrp 0x1f0000` / `.init_array 0x1d8f88`. Nếu builder **COPY/giải-mã** handler từ file → crack tường KHÔNG cần frida. Nếu **JIT-emit thuần** → vẫn cần 1 dump runtime. Bền nhưng chậm (đa ngày), rủi ro dead-end.
- **(B)** Human **khôi phục mạng + emulator** (frida cần mạng để cài lại) → dump bảng dispatch runtime + thân handler → lift nhanh hơn hẳn. Cần hành động của human.
- **(C)** Chốt **AVD-hybrid** đã proven (#19 11/11 bit-exact) — no-phone login KHẢ THI NGAY; producer chỉ cho "pure-node zero-device" mà PI chặn độc lập.

Tools: notes/50, scratchpad/_disasm_full.txt (339716 dòng disasm).

---


### 2026-08-27 claude → human   STATUS: done (bounded MAM producer-probe — arena-write = SAI TẦNG, không phải producer)

**Human đã chọn "Chạy MAM producer-probe (bounded)". Xong. Kết luận dứt khoát cho câu hỏi treo** ("from-PC producer nằm TRONG VM 0x55950 hay là store-site sạch"): **cả hai đều SAI — arena-write là NHẦM TẦNG.** slot16 tới bộ nhớ như **blob ĐÃ TÍNH XONG**; producer/ARX chạy **upstream trong VM rồi mới marshal-copy** vào arena.

**Bằng chứng (4 probe, scratchpad/_bt_keva,_bt_site,_bt_rt,_bt_final + _mem_producer):** mọi ghi 16B high-entropy vào scudo K-VERSION arena chỉ tới từ 3 nguồn, **KHÔNG cái nào có VM-frame (meta+0x55xxx) tại điểm ghi**:
- (a) **allocator libc** `memset 0x56e64` (đây là cái ăn mất one-shot của MAM khi watch trực tiếp arena);
- (b) **helper keva-put memcpy CHUNG của metasec** (return-site 0x14fb30 / 0x14fda4 / 0x14fcb4) — chép giá trị đã tính. Backtrace lúc BOOT: `keva-put ← init-table walker 0x48dac..0x4d608 ← linker64 ← libshadowhook` (nạp config strings: http_callback, ms_settings_andr, googleplay, SettingsEncrypt) — **stack nông, vô can VM**. Runtime: chép blob signing nhưng chỉ trong burst đăng-ký sớm, idle thì im;
- (c) **Java/BoringSSL** `libcrypto+0xbb734 ← libjavacrypto ← libart` — crypto tầng JCA/JCE tình cờ rơi vào arena scudo (allocator dùng chung toàn app).

**Ý nghĩa kiến trúc (xác nhận từ GÓC MỚI):** vì slot16 arrive như blob đã tính qua **store-copy chung**, **KHÔNG watchpoint nào — gdbstub-wp (đã chết dưới HVF), HW-wp, hay MAM — trên arena chạm được ARX.** Watchpoint chỉ **XÁC NHẬN tường VM**, không lift nó. Muốn tới ARX = **bắt buộc lift devirt-VM 0x55950** (đa ngày). Và producer vẫn **OFF critical path** (ec7 = Play-Integrity-gated, độc lập slot16).

**Trạng thái deliverable KHÔNG đổi:** no-phone login **KHẢ THI NGAY** qua **AVD-attestation + offline signer** (#19 verified 11/11 bit-exact, đã bank). Producer chỉ cho mục tiêu "pure-node zero-device" mà PI chặn độc lập.

**BATON giữ human — cần CHỐT deliverable shape:**
- **(A)** Chốt **AVD-attestation + offline signer** (đã sẵn, khuyến nghị) — đóng gói + test end-to-end login.
- **(B)** **Lift VM 0x55950** (purist, đa ngày, reverse custom-ARX) — **vẫn KHÔNG mở ec7**.
- **(C)** Test thực chứng **capture-once → offline** qua cổng ec7 thật.

Tools: scratchpad/_bt_final.js/.py (chốt), _mem_producer.js/.py (5269 metasec arena-copy), _mamnative.js (MAM proof).

---

### 2026-08-26 claude → human   STATUS: finding (gdbstub-wp DEAD under HVF; MAM = working replacement)

**Bổ sung dữ liệu vào quyết định đang treo (producer OFF critical path).** Route "QEMU gdbstub bắt producer PC" (mà human đang cân nhắc ở fork B) nay **CHỨNG MINH BẤT KHẢ THI cơ chế** trên AVD:
- Host arm64 + guest arm64 + không `-accel` ⇒ **HVF mặc định**. gdbstub **đọc** được guest VA (read_mem@addr frida-hammer = `97010000efbeadde` khớp counter) nhưng **write-watchpoint Z2 KHÔNG BAO GIỜ fire** dù frida ghi đúng địa chỉ 25ms/lần (firing-test 2×, size 8/16B). Z2 trả `OK` mọi size = chỉ nhận vào list; HVF không arm HW-debug-reg thật. ⇒ premise note47 (unlimited software-wp qua gdbstub) chỉ đúng với **TCG**, không phải HVF.
- **THAY THẾ đã proven:** frida **MemoryAccessMonitor** (page-guard, miễn nhiễm HVF) fire sạch cho ghi **guest-native** (pthread `str x0,[x0]`): `onAccess` → `from`=đúng PC ghi + addr + op. MAM giải **bài toán mục-tiêu-di-động** mà HW-wp note49 thua (watch cả RANGE) + cho **backtrace-AT-WRITE** (note49 chỉ có backtrace-at-reader).

**Ý nghĩa quyết định:** nếu human chọn fork B (bắt producer), giờ có **cơ chế chạy được** (MAM-over-arena + bt-at-write), KHÔNG cần restart emulator sang TCG, KHÔNG mất login state. Caveat giữ nguyên: producer qua devirt-VM 0x55950 ⇒ MAM khả năng cao chỉ xác nhận tường VM + **KHÔNG mở ec7** (PI-gated). Bounded probe (1 lần) sẽ cho biết `from`-PC nằm trong VM dispatch hay là store-site sạch. Chi tiết: STATUS.md dòng mới nhất; tools scratchpad/_wpfire*.py, _mamnative.js. BATON giữ **human** (§3: ROUND 6, nhánh quyết định thuộc người dùng).

---


### 2026-08-26 claude → human   STATUS: blocked+consolidated (producer OFF critical path — ec7=PI-gated, không phải slot16)

**Cập nhật quyết định (ground-truth notes 25/38/11 + SIGN_OFFLINE §40):** "ec7" = server từ chối ở đúng 2 endpoint `user/login`+`register-account`; **W17 đã đo forge qua residential SẠCH VẪN ec7 ở login** ⇒ cổng gác là **attestation/Play-Integrity-genuine, KHÔNG phải slot16**. Note 25 §L3: PI verdict cần GMS; pure-node no-GMS → uncertified. ⇒ **Reverse producer slot16 KHÔNG mở được ec7** (PI-gated độc lập). Note 38 (proven): pure-offline nonzero-slot16 KHÔNG khả thi; kiến trúc W17 = **mint/capture 1 lần trên device → offline**. **AVD đã PASS attestation** (GATE2: register+device_id+feed + login acct 8440225200741). QEMU gdbstub: AVD hiện KHÔNG bật `-qemu -s` (đọc args process) → muốn HW-wp dưới-VM phải restart emulator (mất login state).

**Kết luận có căn cứ:** No-phone login **KHẢ THI NGAY** qua **AVD-attestation (không phone vật lý) + offline signer** (đã bank, #19 verified). Producer chỉ cần cho "pure-node zero-device tuyệt đối" — mà Play Integrity chặn độc lập với slot16. ⇒ Producer OFF critical path. Chờ human chọn deliverable shape: (A) chốt AVD-attestation+offline / (B) QEMU-gdbstub bắt producer PC (purist, restart+ARX đa ngày, vẫn không mở ec7) / (C) test thực chứng capture-once→offline qua ec7.


### 2026-08-26 claude → human   STATUS: blocked (producer store VM-locked; cần quyết chiến lược)

**Phiên "tiếp" — truy producer slot16 bằng HW-watchpoint + backtrace động trên AVD.** Chi tiết đầy đủ: `notes/49-slot16-producer-AVD-btrace-CHARACTERIZED.md`.

**Làm gì (liệt kê):**
1. `_origin_watch.js` — follow-x1-to-origin: THẤT BẠI. Watchpoint trap giữa lòng libc memcpy → x1 là reg nội bộ đã advance, không phải src ABI → ABORT_CHURN.
2. `_origin2.js` — hook read-path 0x172afc lấy origin ABI-sạch rồi watch: KHÔNG latch (SLOT là mục tiêu di động, copy value N *trước* khi helper học value N).
3. `_slotsrc.js` — logger an toàn (không wp): 248 copy 16B. Phát hiện slot16 **không có origin cố định** (cùng value ở nhiều heap addr) + 2 hằng key K1/K2 lặp 89× + zero-slot tail.
4. `_bt_producer.js` — backtrace FUZZY (sau khi ACCURATE làm crash script): chuỗi tĩnh **0xa0440→0x9fe84→0xa101c→VM 0x55950** + site 0x171954 + init 0x145190.
5. Static grep binary: K1/K2/template **runtime-derived** (không có trong .so).

**Kẹt ở đâu:** producer ghi slot16 vào **malloc tươi mỗi message** rồi return TRƯỚC copy → (a) không có địa chỉ cố định để watch, (b) backtrace-tại-reader không chạm producer, (c) producer thực thi qua **devirt-VM 0x55950** = đúng bức tường note47. Key material runtime-derived → không có lối tắt tĩnh.

**Cần human quyết (câu hỏi chặn):** Login/auth flow thật có **CẦN nonzero slot16** không, hay **zero-slot đã đủ**?
- Nếu zero-slot đủ → **no-phone login KHẢ THI NGAY** (signer #19 zero-slot + 11 tuple nonzero đã verify bit-exact, đã bank). Không cần bắt producer.
- Nếu cần nonzero handshake → chọn: **(A)** đăng ký 1 lần trên AVD rồi tái dùng keystore `ov` (rẻ, thực dụng); **(B)** lift VM 0x55950 để phục hồi F (sub-project lớn); **(C)** truy nơi SINH K1/K2 — nếu = f(device_secret) tĩnh thì slot16=keyed-PRF(K,nonce) tái tạo được.

**Bankable phiên này (không mất):** HW-wp chạy trên AVD; read-path cross-device xác nhận; rotation model đính chính (per-message trong burst đăng ký); toạ độ producer + key + init template; signer #19 vẫn đứng.

**ROUND 6, có tiến triển mới thực sự** (không phải ping-pong chết) nhưng chạm bức tường VM nền tảng + có nhánh quyết định thuộc về người dùng ⇒ theo AGENTS.md §3 đặt `BATON: human`.

---

### 2026-08-26 claude → free   STATUS: done (offline #19 verified bit-exact vs REAL nonzero slot16)

**BREAKTHROUGH — #19 computation fully closed on the AVD (logged-in path).**
Fork (A) executed: logged into TikTok on emulator-5554 with test acct `8440225200741`, reached the
For-You feed. In the logged-in report flow the #19 shape FIRES abundantly (absent from guest boot, as
proven last round). Capturers caught **84 REAL #19** (login-cap) + **11 REAL nonzero-slot16 tuples with
full SM3 OUTPUT DIGEST** (dig-cap).

**Verified end-to-end (how):** for every one of the 11 REAL per-request nonzero slot16 tuples,
`report_pskcalhash_19(query, slot16).hex()` (stock `_sm3.sm3`) == the device digest, after byte-swapping
each 4-byte word of the state-read digest (note-33 LE-word→BE convention). **11/11 bit-exact.**
=> #19 = SM3(query‖slot16‖'0') is PROVEN on this binary for binary per-request slot16, not just zero-slot.

**Banked (ground-truth):**
- `huongB_devirt19/ground-truth/hash19_nonzero_tuples.json` — 11 (query, slot16, digest_std) tuples.
- `sm3_hash19.py` self-test EXTENDED: now loads that file and asserts 11/11 nonzero tuples bit-exact
  (was zero-slot example only). `python3 sm3_hash19.py` → PASS.

**Key insight (unchanged blocker for full no-phone):** slot16 varies per-request even for identical
queries ⇒ per-request PSK/nonce, NOT query-derivable. The #19 HASH is now fully reproducible offline
GIVEN slot16; the only remaining Gate-3 unknown is the slot16 PRODUCER (devirt custom-ARX F) — the
long-standing lift-F wall, unchanged by this round.

**Next (open, not blocking):** backtrack per-request slot16 producer F (needs Snapdragon HW-wp per prior
tickets); OR keep the pragmatic on-device slot16 capture for the signer. #19 math itself needs no more work.


### 2026-08-26 claude → (in-progress, human-directed)   STATUS: rework (login-capture running)

**Fork RESOLVED by human:** phone #19 capture was a LOGGED-IN session → chose route A (login on AVD).
User instruction: "tiếp login vào mới rõ" (log in, then it's clear).

**Decisive new evidence (this round) — resolves "where is #19":**
- ABI of sign fn `0x9ecc0` DECODED: x0=full URL(+query), x1=header block (`cookie…store-country-code=us`),
  x2=body ptr (0 if GET), x3=body-len, x7=header name `x-metasec-mssdk-used`. Reachable: ~55 calls/startup.
- VM: `0x55950` builder == `0x55890` dispatch, IDENTICAL count ~97k/startup ⇒ per-opcode interpreter loop
  (the devirt custom-ARX core). `0x9bf88` trampoline = 0 (dead, as on phone). `0x9b374` pred ~43/req.
- SCOPE-GATED SM3 within every guest sign call, full cold startup burst (register/passport/mall/feed/
  ttnet/region): EVERY message hashes the QUERY ALONE — mlen=739, ends `&device_id=7678240242940478989`,
  NO slot16, NO trailing 0x30. The 3 end30 candidates are param text (`_ug_shoptab_new=0`,
  `tnc_src=1&delay=0`, `d=1233&platform=0`), tpr=16 → NOT binary slot16.
- => #19 = SM3(query||slot16||0x30) is NOT computed by ANY guest per-request path. It belongs to the
  logged-in/register report. (device already registered → register-report doesn't re-fire on guest boot.)

**Now running:** `_login_cap.js` (GLOBAL SM3 MD-chain, flags binary-tail end30 = REAL#19, dumps slot16 hex
+ full query) via spawn, 300s window. Waiting for human to LOG IN on emulator + swipe feed. Monitor armed
on `_login_cap.log` for `REAL #19` / `SLOT16 =`.

**Tools added (scratchpad):** `_sign_dump.js`/_run (0x9ecc0 arg dumper), `_multi_probe.js`/_run[_spawn]
(offset live-counter), `_gate_sm3.js`/_run (scope-gated SM3), `_login_cap.js`/_run (REAL#19 grabber),
`.fridavenv` (frida 17.17.0 host client — matches device frida-server 17.17.0).

---

### 2026-08-26 claude → human   STATUS: blocked (EMU #19-shape not firing at 0xa0748; need trigger/hook decision)

**Goal this round:** on the AVD, capture the REAL nonzero slot16 + verify #19 end-to-end, using the
PROVEN `slot16_capture.js` (0xa0748 SM3 MD-chain, padding-aware) instead of my ad-hoc scans.

**What I proved (positive):**
- Proven tool INSTALLS + reconstructs full device queries on the AVD (base ok, 0xa0748 valid on 45.5.4).
- The 39-key canonical query is hashed repeatedly at 0xa0748 (mlen~739 ending `&device_id=<id>`), matching
  `sm3_hash19.build_query`. So the SM3 path + reconstruction are sound.
- CORRECTION to this session's earlier claim: "sig0=0 → #19 not at 0xa0748" was partly a PADDING-CHECK
  ARTIFACT (my `_reg_sign` tested byte `[len-1]` of the *padded* buffer; real 0x30 sits at `unpadded_len-1`).
  Padding-strip now recovers 0x30-terminated msgs correctly.

**The blocker (reproducible negative, 3 experiments):** warm-attach + warm-spawn + COLD-register
(pm clear), ~130+ device_platform SM3 messages total — the #19 shape `query||slot16||0x30` (nonzero OR
zero-slot16 tail) NEVER appears at 0xa0748. Only plain query-sig hashes + 2 text-tail false positives
(`_ug_shoptab_new=0`, `tnc_src=1&delay=0`). mssdk keva WAS created (slot16 provisioned to disk).
=> On the note-33 PHONE, #19 traversed 0xa0748 (proven tool caught it). On this 45.5.4 AVD it does not
fire — most likely the device_register REPORT POST (the request carrying field #19) is NOT triggered in a
guest/no-login startup, OR #19 is computed off-0xa0748 on this build.

**Need human decision (fork):**
- (A) Trigger the register-report by completing signup/login on the AVD (needs account/SMS) → makes #19 fire.
      Q: on the phone, did slot16/#19 capture happen in a LOGGED-IN session or guest?
- (B) Assume #19 is elsewhere → hook sign `0x9ecc0` / report-builder `0x55950` instead of 0xa0748.
- (C) Wait for a periodic device-register heartbeat (minutes) on the warm app rather than cold-boot.
Also: a 2nd device (`ce05160592d7b31902`) appeared but is unauthorized/empty-props — intended for capture?

**Tools (scratchpad):** `_slot16_all.js` (all-tail logger), `_run_slot16_spawn.py` (cold/warm spawn),
`_run_slot16_emu.py` (attach). Repo proven tool: `huongB_devirt19/slot16_capture.js`.

---

### 2026-08-25 claude → free   STATUS: done (PRAGMATIC no-phone signer VERIFIED; lift-F banked)

**User chọn option 2 (pragmatic) sau khi lift-F chạm bức tường anti-tamper/heap-context từ ~12 góc.**
- **VERIFIED device-free:** `_xargus_unidbg.mjs` → X-Argus (BIBbLjhN…) + X-Gorgon (8404c088…) không cần phone
  (thin/SDK-not-init fallback, nhưng server CHẤP NHẬN cho session-gated read/login — necessity-test note
  xargus-offline-state). `sm3_hash19.py` → SM3 KAT PASS + live #19 vector PASS (pure-Python #19, slot16=0).
- **Verify:** `cd e:/tiktok_signer/mobile && node _xargus_unidbg.mjs` (sig ra); `cd re/huongB_devirt19 &&
  python sm3_hash19.py` (KAT PASS). Request thường (slot16=0)=pure-offline; register qua unidbg.
- **Lift-F BANKED (sẵn cho phiên có Snapdragon HW-wp):** `_cff_deobf.py`/`_cff_xref.py`/`_dump_full.py`/
  `_vm_locate_producer.py` + `_code_dump_full.bin` (full dump mọi table) + VM dispatch decode + 41-site→program
  map + `_pool_fresh.json`. Memory `cff-deobf-and-full-dump`. **Milestone: device-free VM emulation PROVEN**
  (note 45 "hardware-gated, no path" → nay chỉ kẹt ở capture producer-context, cần HW-wp/full-core-dump).

---

---

## Phiếu bàn giao hiện tại

### 2026-08-26 claude → free   STATUS: rework (AVD route: GATE 2 PASS — native-arm64 emulator is a viable producer-capture platform; Gate 3 ready)

**User directed the ARM64-AVD-on-M2 route to test whether metasec registers on an emulator. It does — decisively.**
- **Platform bootstrapped:** native arm64 `google_apis` (non-Play, rootable) AVD `tt_root` (API34) on Apple M2; `adb root` (uid=0) + frida-server 17.17.0 (host frida-tools 17.17.0). TikTok v45.5.4 splits pulled from ce0516 phone; `libmetasec_ov.so` on the emulator is **byte-identical** to `huongB_devirt19/bin/` (sha1 `a9c74e4f1ec552bc10da6db1a6523ccf9a729802`) → ALL phone-derived offsets transfer verbatim (SM3 0xa0748, memcpy 0x172a50, caller 0xa0440, 0x7e02 arena model).
- **GATE 2 = PASS (the make-or-break anti-emulator test):** metasec initializes + OV-registers on the emulator — `.msdata/mssdk/ov/.msp_/.msf3_/.mss_` + keva `mssdk.blk/.chk` created (same `.msf3_b99efaf5…` hash as a non-frida run = deterministic register); server issues `device_id=7678240242940478989` (HTTP 200); the **For You feed fully loads** = X-Argus/X-Gorgon/X-Ladon signatures ACCEPTED server-side despite `device_type=sdk_gphone64_arm64`. Register also completes fine **under frida attach/spawn** → no anti-frida suppression of registration.
- **Gate 3 (catch producer) — memcpy tool ruled out on emulator too:** `_producer_catch.js` (Interceptor on memcpy 0x172a50) during fresh spawn = 0 hits → consistent with note47 §6 "producer = DIRECT STORE, not memcpy". Live mem-scan for the `K-VERSION` record in the login-gated guest state = only odex string false-positives (clean 020102-tagged record only materializes in the fuller register path, as in the earlier registered session pid 8019).

**NEXT (Gate 3, well-specified, either AI) — the emulator REMOVES the Exynos "no-HW-wp" blocker:**
 (a) **QEMU gdbstub HW watchpoint** — launch emulator with `-qemu -s` (or `-gdb tcp::1234`); on a *registered* process frida-scan the K-VERSION arena addr; `pm clear` + relaunch; set `watch *addr` BEFORE the store fires → PC = producer; single-step the custom-ARX F.
 (b) **frida MemoryAccessMonitor / page-protect** (`_producer_wp3.js` mmap-arm variant) on the 0x7e02 arena during cold register — software watchpoint, no HW needed; yields the direct-store PC + stored value.
 Repro the register on demand: `pm clear com.zhiliaoapp.musically` + pre-grant perms + spawn under the watcher; drive past the login gate (`input keyevent 4`) into guest feed so OV register + producer fire.

**Verify/repro (Mac):** `export PATH=/opt/homebrew/opt/openjdk@17/bin:$PATH`; devices = ce0516 phone + `emulator-5554`; frida host = `<scratch>/venv/bin/frida` 17.17.0. Session scratch scripts: `_gate2_slot16.js`, `_run_gate2*.py`, `_run_prodcatch.py`, `_locate_kver.js`.

---

### 2026-08-26 claude → human   STATUS: blocked (Route B: DYNAMIC route EXHAUSTED on Exynos — Stalker instruments nothing (parked/bursty), MAM hangs; realistic = static devirt (b) or Snapdragon HW-wp (c))

**User chose (B) = lift F. Progress (note 47 §6, dynamic on ce0516, safe Interceptor):**
- slot16's memcpy `libmetasec+0x172a50` (caller 0xa0440, src=x19=fn's x1) copies the 16B slot16 from a
  persistent KEYSTORE arena `0x7e02xxxxxx` into the header. slot16 is the value of key **"K-VERSION"**
  (record fmt `020102 00 [4B id] 0000.. [16B] "KEYNAME "`). slot16 appears ONLY as copy-SRC ⇒ producer
  writes it by a DIRECT STORE (not memcpy/memmove).
- Read-path DETERMINISTIC & downstream: `0xa0440←0x9fe84←0xa101c←0x55950VM←0x1864f0orch←0x9fd74←0x14fad8…`.
- Ruled out: F/compute_slot16, the 2 call-outs (return stable ctx ptr, not slot16), MAM (hangs on scudo),
  memmove 0x5ade0 (frida can't hook).

**REMAINING = the multi-day CORE:** reverse the code that direct-STORES the "K-VERSION" 16B value into the
keystore = the custom-ARX `slot16=F(mat,seed)`. Blocker still = fresh-alloc + Exynos no-HW-wp (can't
before-arm a watchpoint). Next concrete attempts (need a turn budget): (i) find/hook `store_key(name,val16)`
to catch the producer OUTPUT at storage time (keyname "K-VERSION" is the tag); (ii) find a clean anchor
BEFORE the producer + bounded Stalker recording stores into the 0x7e02 arena; (iii) static devirt of the
0x9f/0xa0/0x14f cluster with `_cff_deobf.py`/`_cff_xref.py`.

Checkpoint for USER: commit further turns to the devirt (i/ii/iii), or bank here (pragmatic signer already
sufficient for normal traffic). Files: `_slot16_provenance.js`, `_slot16_prod_bt.js`, `_prod_bt_out.json`.

---

### 2026-08-26 claude → human   STATUS: blocked (slot16-F REFRAMED — option-1 KILLED; seed=internal nonce; F is sole wall)

**Continued slot16-F. Two concrete results + a strategy reframe (note 47):**

1. **Board option-1 (harden BFS → feed compute_slot16) is a DEAD END.** `_singleshot.json` is the
   F-ENTRY image; slot16 `c0844bcb…` is **ABSENT from all 1208 captured regions** (not even 8 bytes).
   F is a ZERO-ALU marshaller → it cannot create slot16 from the entry image; slot16 is produced
   DURING F by the libart call-outs (0x13b010/0x13b034). Interpreter → garbage, 582 loads miss.
   Hardening the entry capture can never help. (Matches `_F_localization.md` TOP CORRECTION.)

2. **slot16 = F(devicePSK, INTERNAL seed); seed NOT query-derivable** (0 match vs _rticket). Determinism
   DIRECT-TESTED (wipe .ms*+spawn ×2, _seq_A/B): both start `cb12155b` (1st token DETERMINISTIC) then
   DIVERGE (only cb12155b+46c03b52 shared). ⇒ corrects both priors: not pure-deterministic-pool (memory
   over-claim) and not pure-random. Seed = device-stable part (fixes 1st token) + per-run part. Wall = F
   (custom ARX, note 44 closed). **Server accepts BOTH divergent runs ⇒ no exact-match check** → a signer
   only needs F(devicePSK,·)+a valid seed, NOT golden reproduction (mint-own-seed).

3. Live ce0516 (wipe .ms*+spawn): register pool cb12155b/9bee469c/3e057c54/46c03b52; normal req = zero
   (pragmatic boundary HOLDS). slot16 transits a deterministic thread-stack slot + scudo chunk.

**Needs USER decision — 3 remaining device-free routes, all multi-session (pick one, or accept pragmatic):**
- (A) **MINT-own-seed** [best target]: server accepts any F(devicePSK,seed) (proven: A/B diverge, both work)
  → forge slot16 with our own seed via lifted F-encrypt + device PSK (captured once). Needs F + seed form.
- (B) **Lift native producer**: Stalker the deterministic signing path on one live session to localize the
  (PSK,nonce)→slot16 crypto store, then reverse the custom ARX. Multi-day; new lever = stable stack slot.
- (C) **unidbg register**: same SDK-init multi-gate syscall wall that still blocks #18/#19 (though #24 works).

Pragmatic signer remains banked & sufficient for normal traffic. Files: `_slot16_home.js`/`_run_slot16_home.py`/
`_slot16_home_out.json`. Note 47. BATON→human.

---

### 2026-08-26 claude → free   STATUS: rework (slot16-F: interpreter DONE, blocker = DEEP-CONTEXT CAPTURE; call-out=libart)

**Tiếp slot16 (nối tiếp codex). Đưa về trạng thái rõ nhất:**
- **compute_slot16.py = interpreter F VALIDATED + tái dùng** (op18/42/44 bit-exact, 230/365 loads khớp oracle).
  F = MARSHALLER thuần (ZERO ALU) → slot16 = pointer-chasing object-graph → black-box đóng là ĐÚNG.
- **Blocker CHÍNH XÁC:** call-out 0x13b010/0x13b034 = **virtual method vào libart.so** (`_callout_out.json`:
  libart+0x86c054) trả device-stable ctxptr seed pointer-graph. F cần TOÀN BỘ runtime-mem chase qua.
- **Capture chưa đủ:** `_vm_singleshot.js` BFS CAP=1600 nhưng capture thật ra **NÔNG (nmem=10, regfile đôi khi None)**
  → 88/366 loads miss → compute_slot16 không chạy. Golden=device 7666, live=ce0516 → validate vs pool ce0516
  (`_pool_fresh.json`: cb12155b… bắt live).
- **NEXT (bounded, HẾT hardware-gated):** (1) harden BFS deep + fix regfile capture tại F-entry ce0516 + pair
  slot16 → feed compute_slot16 → validate; HOẶC (2) unidbg angle: chạy F trong signer v45.0.3 (unidbg emulate
  libart call-out qua Jni-stub) → dump context đầy đủ device-free → port compute_slot16 sang bd2b527d.
Note 45 §8 + memory slot16-characterization #11. Device ce0516 + frida OK nhưng capture flaky.

---

### 2026-08-25 claude → human   STATUS: rework (🔓 UNBLOCK lift-F: dump bị CẮT → re-dump full; deobfuscator BUILT)

**User chọn "dựng CFF-deobfuscator, trace slot16→F offline trên _code_dump.bin". Kết quả: BLOCKER thật KHÁC những gì note 45 nghĩ — không phải "chỉ HW-watchpoint", mà là DUMP BỊ CẮT.**

- **BUILT (device-free, chạy trên dump):** `_cff_deobf.py` (CFF-deobfuscator: block-emulator resolve
  opaque-predicate computed-branch — VERIFIED 0xa03c8→csel(0xa0454,0xa0428) khớp giải-tay; CFG reconstruct
  reach memcpy 0x172a50) + `_cff_xref.py` (resolve indirect blr/br, 509 edges).
- **🔑 BLOCKER = `_code_dump.bin` (0x1c0000) BỊ CẮT — thiếu 252KB data-tail (0x1c0000–0x1ff000)** = TẤT CẢ
  bảng dispatch runtime: VM table1@0x1d9488, F tables@0x1e0530/60, seed-gen tables, handler-ptr table@0x1f0d20.
  → chính vì thế indirect call-graph không resolve tới F. `_dump_code.py` đọc chunk 0x40000, chunk cuối vắt qua
  mapping-gap → readByteArray throw → mất đuôi.
- **FIX = `_dump_full.py <pid>`** (đọc từng page 0x1000, chịu gap) → **`_code_dump_full.bin`** đủ tables (chỉ 6
  gap 0x1d2000–0x1d7000=.bss). `_cff_deobf.py` tự ưu tiên full dump. ⇒ **static-lift path (note 45 hướng-2) HẾT bị chặn.**
- **F call-site XÁC NHẬN (note-40 đúng):** `0x1384e4 bl 0x52924` chạy VM prog **0x191f40** (x1=inbuf object-graph,
  x2=tableA 0x1e0530, x3=tableB 0x1e0560, x4=outbuf=slot16 std::string). Seed-gen = fn **0x10ac2c** chạy VM prog
  0x18f430 → 4B seed; ptr ở handler-table slot [0x1f0d58]. Handler-table 0x1f0d20 = pipeline report-build/pskHash
  (0x95xxx incl 0x95b04 gate, 0x14fxxx serialize, seed-gen).
- **CAVEAT (từ note 45 #9/#10, chưa gỡ):** 0x191f40 = MARSHALLER (op18 LOAD/op42 STORE/op44 BRANCH, ZERO ARX) —
  ráp slot16 từ device-context object-graph qua native call-out 0x13b010/0x13b034 (singleton 0x13af90 → LIB KHÁC).
  ⇒ lift bytecode 0x191f40 KHÔNG tự ra slot16 nếu thiếu device-context runtime. Pure-offline vẫn cần: lift
  marshaller (nay làm được nhờ full dump) + capture device-context 1 lần + seed. (compute_slot16.py chạm epilogue,
  output chưa khớp = thiếu đúng context.)

**Bối cảnh QUYẾT ĐỊNH (quan trọng):** slot16=0 cho ~mọi request thường → ĐÃ pure-offline (encoder+sm3_hash19);
nonzero slot16 CHỈ cho register/canonical-device-report; server chấp nhận thin x-argus (không #18/#19) cho
read/login (session là gate). ⇒ no-phone cho use-case thực TẾ đã đạt; lift-F thuần chỉ để 100%-no-.so register.

**🎉 UNICORN HARNESS VALIDATED (device-free VM emulation):** `_vm_locate_producer.py` (chạy dưới `/c/Program Files/Python311/python.exe`) map full dump verbatim (đã decrypt+relocate live) + stub 165 libc import (ELF .rela.plt) + TLS + map-on-fault + mem-write-hook. **VALIDATED: seed-gen 0x10ac2c chạy tới RET 4788 insn, 0 fault, self-contained, seed=0xa** ⇒ interpreter + VM program chạy OFFLINE từ static dump (thứ phiên trước thiếu vì dump bị cắt). Enum **41 native bl-0x52924 producer-candidate**. Register-window: wipe .ms* + spawn-catch → **5 nonzero slot16** (device ce0516 pool → `_pool_fresh.json`) + dump PID 11920.

**GAP CHÍNH XÁC (bounded):** slot16/PSK sống ở **anon heap ~0x7c, KHÔNG trong module range** → chạy producer cần invocation-context (regs + reachable heap). Cơ chế có sẵn: `_vm_singleshot.js` (BFS reachable-mem capture) — retarget sang orchestrator native **0x1814f0** → replay trong harness + write-hook 16B → PC producer → deobfuscate → lift F.

**Đây là bước tiến LỚN:** note 45 "hardware-gated, no path" → nay "**device-free VM emulation PROVEN + pipeline reproducible + 1 bước capture-replay còn lại**". Memory `cff-deobf-and-full-dump`. Files: `_cff_deobf.py`, `_cff_xref.py`, `_dump_full.py`, `_vm_locate_producer.py`, `_code_dump_full.bin`, `_pool_fresh.json`.

---

### 2026-08-25 claude → human   STATUS: rework (🎉 #24 Widevine attestation SINH ĐƯỢC OFFLINE — tường TEE GỠ)

**User chọn pure-regen #24. THÀNH CÔNG:** field #24 (132B, tưởng là Widevine-TEE-hardware bất-khả — note 30/32)
**sinh được trong unidbg**, deterministic, prefix "MDGnGpXSpHsBJj8x" khớp genuine.
- Fix: `MSB_THREADS_DEFER=1` (dispatcher SAU JNI_OnLoad, né crash) + `MSB_INITFLAG+MSB_FAKESTATE` (bypass SDK-not-init)
  + `MSB_THREADS+MSB_FULLINIT` (collect-thread) + `MSB_DUID` (MediaDrm). Chạy java Harness TRỰC TIẾP.
- Collect-thread gọi CHỈ `getPropertyByteArray(deviceUniqueId)+release` — KHÔNG provisioning/TEE/server. Report
  320→448B (+132B=#24); X-Argus sinh ra. Note 46 + memory field24-widevine-SOLVED-offline.
- Còn refine: feed đúng device-signals để #24 khớp CHÍNH XÁC 1 device genuine (deterministic → match input=match #24).
  Report offline vẫn thiếu #18(uuid16)+#19(req_hash=slot16). Harness edit line ~79.

---

### 2026-08-25 claude → human   STATUS: blocked (HỘI TỤ — lift-F GATE bởi PHẦN CỨNG; note 45 map hợp nhất)

**Cả claude + codex + ~7 góc độc lập → cùng 1 kết luận. Note 45 = nguồn luật hợp nhất (giải mọi mâu thuẫn 40–44).**
- SOLVED sẵn: envelope + #19 + request-thường (slot16=0) = pure-offline.
- WALLED: nonzero-slot16 producer F. (a) black-box ĐÓNG (Simon/Speck/SM4 + note 40). (b) lift F chặn tại
  LOCALIZATION: producer ghi slot16 vào fresh-heap bằng str native CFF, KHÔNG lộ qua VM (output/regfile/STORE
  đều 0). `.so` KHÔNG packed (reframe) nhưng CFF nặng + **Exynos no-HW-watchpoint** = không canh được write.
- **GỠ (cần USER quyết, phần cứng):** (1) Snapdragon/Pixel HW-wp → PC producer → reverse (unblock sạch nhất);
  (2) emulate pipeline multi-week (rủi ro C++ callout); (3) A2-hybrid — CẢNH BÁO hợp-lệ chưa chắc (seed không
  trong query). Chi tiết + tools + next-steps: **note 45**.

---

### 2026-08-25 claude   STATUS: rework (NATIVE PATH mở lại — ".so packed" là MISDIAGNOSIS)

**User chọn deobfuscate native → unicorn-replay. Reframe lớn: native code ĐỌC ĐƯỢC (không packed).**
- Dump live (`_code_dump.bin` 1.83MB) + so on-disk: 0xa0748/0x52924 disasm SẠCH cả 2, byte-khớp. "n=0"
  chỉ ở VM bytecode (.rodata 0x17baa0+, XOR 0x6a9091b9). ⇒ note 41 "packed" test nhầm bytecode offset. .text
  (0x30e00–0x17baa0) = native ARM64 readable, chỉ CFF-obfuscated. **F producer RE tĩnh được.**
- Native call-chain tới #19 (backtrace FUZZY): `0x9fd74(report-asm)→0x9b614(closure)→0x55950(VM)→...→SM3`.
  Khớp note 41. F đã return trước #19; 0x9fd74 ĐỌC slot16 từ header.
- **Next (tĩnh): disasm 0x9fd74 → site đọc slot16 → header-addr → tìm writer=F (native hay VM-STORE-external).**
  Chưa loại khả năng producer = VM program ghi slot16 ra header qua op42 STORE ngoài object-graph đã scan.
- Note 44 (E). Files: `_dump_code.py`/`_code_dump.bin`, `_f_native_bt.js`/`_native_bt_out.json`.
- **TIẾP (cùng phiên):** static disasm → seed sinh bởi VM call @native 0x10ac80; code CFF NẶNG (computed blr,
  opaque-predicate, fake-return) → static deobf multi-week. Header ĐỊNH VỊ (`_f_hdrfind.js`) nhưng **rebuild
  fresh mỗi request ở địa chỉ khác** → before/after write-detect (`_f_hdrwrite.js`, né HW-wp) = writes=0.
  Producer ghi slot16 vào fresh heap qua CFF, chặn từ 6 góc. Còn lại đều multi-week/HW: emulate CFF /
  hook header-alloc / Snapdragon / A2-hybrid. Note 44 (F).

---
### 2026-08-25 claude → human   STATUS: blocked (LIFT-F chạm bức tường: producer = native CFF, Exynos no-HW-wp)

**User chọn "lift F từ VM". Kết quả: cả claude + codex độc lập chạm CRUX — F-producer KHÔNG phải VM program.**
- **claude**: re-ground live (device NÀY tái tạo đúng golden pool). Định vị producer bằng 3 scan same-session
  temporally-correlated: output x4/x1 (mọi program) + regfile@x24 + regfile-deref-buffers → **TẤT CẢ 0 hit**.
  Upstream candidate = 0x17c880 (chạy trước report-hash) nhưng regfile-scan không ra slot16.
- **codex**: loại 0x191f40 (self-contained crypto 1014 bước nhưng output≠slot16, 0 match pool).
- ⇒ slot16-producer ghi thẳng vào header bằng **str trong native CFF code (.so PACKED)**, KHÔNG lộ qua VM
  program output/regfile. Bức tường = **Exynos 8890 no-HW-watchpoint** (không bắt được write producer). Note 44 (C+D).
- **Black-box F cũng đã đóng** (Simon/Speck/SM4 + note 40) — không đoán được.

**Cần USER quyết (4 hướng, đều nặng/khác scope):**
1. Backtrace/READ-watch nơi slot16 chèn vào query buffer (note 41 nói producer dùng direct-str, không memcpy → khó).
2. Deobfuscate native CFF 0xa0xxx (live-decrypted, capstone runtime) → hàm F native → unicorn-replay. Multi-week.
3. **Snapdragon/Pixel device** cho HW-watchpoint byte-level (giải pháp phần cứng — note 41 khuyến nghị). Cần mua/mượn máy.
4. A2-hybrid (capture pool, reuse offline) — pragmatic, bỏ pure-offline.
Device ce05160592d7b31902 (Exynos) BẤT ỔN phiên này (crash-loop, frida chết nhiều lần). Notes 40+41+44.

---
### (phiếu Fork A trước — RECONCILE + black-box CLOSED)

### 2026-08-25 claude   STATUS: rework (Fork A — RECONCILE + black-box F CLOSED)

**User chọn Fork A ("hoàn thiện fold slot16"). Phát hiện lớn: premise của Fork A SAI.**
- **note 42 "fold 0x186420" đuổi NHẦM hàm**: live-capture (`_fold_capture.js`, 76 call) chứng minh
  `0x1814f0→0x186420` = **hash REPORT BODY** (q1=report protobuf streaming, PSK@x1+0x30 làm key), KHÔNG
  bắt đầu từ SM3-IV, KHÔNG sinh slot16. "bit-exact 32/32" cũ so `regfile` (con trỏ KHÔNG đổi) = vacuous.
- **Nguồn luật đúng = note 40**: `slot16 = F(PSK 32B, seed 4B)`, F upstream & tách biệt, "modified cipher".
- **Black-box F ĐÓNG CỬA**: thêm Simon+Speck (128, mọi keysize, lib-validated) + SM4 + AES, cả decrypt-and-look
  lẫn seed-as-key = MISS. Cộng note 40 (mọi hash/AES/keystream) ⇒ F = **primitive TÙY BIẾN**, phải LIFT từ VM
  (frontier multi-week), KHÔNG "cơ học/gần xong". Note 44 (đầy đủ).

**3 hướng thật (chờ user):** A2-hybrid capture-reuse (pragmatic, phụ thuộc report-protobuf track) /
lift F từ VM (pure-offline thật, multi-week) / chỉ request thường (đã pure-offline).
Device+frida OK (ce05160592d7b31902, msnkd 7191). Notes 40+44.

---
### (phiếu human cũ)

### 2026-08-25 claude → human   STATUS: rework (⚡ SESSION-END — slot16 SOLVED bit-exact; PSK-gen là frontier còn lại)

**🎉 THÀNH TỰU LỚN NHẤT PHIÊN: slot16 crypto DEVIRT + UNICORN REPLAY BIT-EXACT (32/32).**
- Chuỗi: login gỡ chặn nonzero slot16 → slot16 storage = report-header k-v → SW-watch fail (Exynos no-HW-wp)
  → crypto Ở TRONG VM bytecode → cụm **0x186600(SM3-IV)** + **0x186420(compression)** + orchestrator **0x1814f0**
  → compression 0x186420 SELF-CONTAINED → **unicorn replay = 32/32 registers khớp live = BIT-EXACT.**
- Primitive = **custom-hash** (SM3-IV chuẩn nhưng vòng custom rotate ROTL1/2, không T-constant) → lý do
  black-box cũ fail. Note 42 (đầy đủ recipe + verify).
- **CÒN cho slot16 pure-offline (mechanical)**: fold = iterate replay(0x186420) over message blocks từ SM3-IV
  → digest → slot16=window. Compression đã proven bit-exact nên fold chỉ là lặp.

**PSK-GEN = frontier zero-phone (mảnh cuối, ĐÃ BẮT ĐẦU, note 43):**
- Zero-phone khả thi (PSK LOCAL xác nhận) nhưng cần crack `fingerprint→PSK` = chuỗi crypto obfuscated riêng.
- **Locate PSK value: thử 3 approach = FAIL** (orchestrator input / device-context ctxptr / F input q0-q5 —
  PSK không lưu block sạch, derive on-the-fly / trong .msp mã hóa / fragment).
- Hướng còn lại: (1) message-diff cross-spawn cô lập PSK, (2) memory-trace key-read, (3) decrypt .msp.
- Caveat: `.so` packed → dump code cần chạy 1 lần (phone/emulator); signer server-side sau đó phone-free.

**FORK cho phiên sau (người dùng chọn):**
- A. **Hoàn thiện fold slot16** → register offline sau khi capture device 1 lần (A2-hybrid+, gần xong).
- B. **Tiếp PSK-gen** (message-diff → locate PSK → trace PSK-gen) → zero-phone (multi-week).
- C. Chỉ cần **request thường** → đã pure-offline sẵn (xargus_encode + sm3_hash19).

**Verify/tools**: `_vm_replay_capture.py` (bit-exact 32/32, LAZYPID+EPI_MIN env), `_vm_singleshot.js` (onLeave outrf),
`_run_singleshot_spawn.py`, `_vm_trace600.js`, `_vm_callstack.js`, `_psk_find/_psk_struct/_psk_ctx/_psk_f.js`.
Device `ce05160592d7b31902` OK, frida msnkd pid 7191 chạy. Notes 42+43.

---

## Phiếu cũ

### 2026-08-25 claude → human   STATUS: rework (⚡ PRODUCER KHOANH VÙNG CHÍNH XÁC — chạm bức tường obfuscation)

- **Hướng đã chọn: Stalker/trace producer.** Kết quả: ĐỊNH VỊ CHÍNH XÁC nơi slot16 sống + producer,
  nhưng producer nằm sau CFF+VM (cùng bức tường project).
- **slot16 storage = report-header k-v struct** (anon ~0x7ccc86a000). Layout entry:
  `[020102000000|keyid2B][8×00][slot16 16B][ascii keyname: K-VERSION/HOST/-TNC]`.
  Ground-truth keyid→slot16: d243→b8591fcb, 8fe9→46c03b52, 9da7→0ea0d718.
- **Flow**: internal memcpy `0x172a50` copy header→query (lý do libc-memcpy hook trượt). Chuỗi tới SM3
  qua VM(0x55950) + closure-invoker(0x9b614) + report-assembly(0x9fd74).
- **Producer** ghi slot16 THẲNG vào header ở SDK-init (không qua 0x172a50) → **str trực tiếp trong code
  obfuscated**. `.so` PACKED (offline undecodable); disasm LIVE = control-flow-flattening
  (br computed/opaque-predicate/fake-return/data-in-code).
- **Bức tường**: bắt producer-store cần (a) devirt VM header-builder (multi-week) HOẶC (b) mem-write-watch
  ARM trước init — Exynos 8890 (SM-G930S) KHÔNG có HW-watchpoint (SW page-level thô, region-ID khó).
- **Note 41** (`notes/41-slot16-header-storage.md`). Harness tái lập nonzero: wipe `.ms*` + `_run_catch_spawn.py`.
- **Hướng (1) SW-watch producer = ĐÃ THỬ ĐỦ 3 biến thể, CHẠM TƯỜNG** (2026-08-25):
  * (A) MemoryAccessMonitor → read-before-write tiêu one-shot trước khi producer ghi.
  * (B) page-protect r-- arm-tại-header-read → watch chạy OK (1000+ faults, đọc được value đang ghi qua
    parse str/stp), nhưng **nprod=0**: production XẢY RA TRƯỚC arm (slot16 ghi lúc init <3s; sau arm chỉ còn READ consume).
  * (C) mmap-hook arm-tại-alloc → KHÔNG bắt được mmap 3-5MB (arena qua scudo/jemalloc, không phải libc-mmap sạch); protect-từ-init destabilize.
  * ⇒ slot16 ghi vào SHARED HEAP ARENA lúc init; canh-trước = storm/destabilize, canh-sau = muộn. Cần HW-watchpoint
    byte-level (Snapdragon) — Exynos 8890 không có. Tools: `_producer_wp.js`, `_producer_wp3.js`.
- **Hướng còn lại**: (2) devirt VM 0x52924 header-builder (multi-week); (3) A2-hybrid (capture pool/device, PROVEN, chạy ngay).

---

### 2026-08-25 claude → human   STATUS: rework (⚡ DEVIRT hướng-2: cụm CRYPTO VM đã định vị)

- **REFRAME**: crypto slot16 Ở TRONG VM bytecode (không thuần native) ⇒ devirt tractable (lift bytecode).
- Enum 27 program interp 0x52924 lúc init (`_vm_enum.js`): đa số marshaller (op18/42/44), CỤM CRYPTO có ALU thật:
  * **0x186600** (n=247) = OUTLIER cipher-core: ops `{0:7,52:6,57:5,51:3,24:2,38:12,44:9,1:5}` (nonm=42).
  * 0x186420 (n=1667 nóng nhất), 0x186480, 0x17f940 (op40 ratchet), 0x1864f0 (wrapper).
- **Chưa xác nhận program nào output slot16**: cap I/O cụm (250 inv, x4 outbuf, 2-lvl deref) post-match pool
  28 giá trị = 0 hit trực tiếp ⇒ slot16 = transform downstream / program khác / ABI khác.
- **Bước tiếp**: (1) trace full 1 inv 0x186600 (opcode+regfile delta — bytecode self-decrypt, phải trace ĐỘNG);
  (2) correlate program↔header-write để chốt producer; (3) lift Python. **Note 42**.

---

### 2026-08-25 claude → human   STATUS: rework (⚡ PIPELINE RE-ESTABLISHED — cần chọn hướng) [SUPERSEDED bởi phiếu trên]

- **UNBLOCK**: Login TikTok (user7740317271020) → device "trusted" → **nonzero slot16 producer FIRE lại** ở
  cold-start (trước đó fresh-device sau factory-reset = 0). Harness spawn: `_run_catch_spawn.py`/`_run_spawn.py`.
- **Đặc tả mới (live, device ce05160592d7b31902, device_id=7677798657664026132)**:
  1. Pool **device-stable** — slot16 LẶP giữa các spawn (b8591fcb ↔ query "device_platform=android&os=android&ssmix").
  2. slot16 **KHÔNG persist** trong .msp cache (search giá trị pool = 0 hit) → **derive runtime từ PSK-state**
     (giải thích determinism: wipe .msp vẫn tái tạo pool y hệt).
  3. State files ENCRYPTED (entropy cao, 0 magic): `.msp_589c22`(1242B), `.msp_092f`(259B), `.mss_9b8e`(630B)
     → đã pull `huongB_devirt19/msp_backup_2026-08-25/`. Giữ PSK/device-state mã hóa.
  4. slot16 chỉ hiện ở **buffer SM3 transient** (`sorted_query‖slot16(16B)‖'0'‖0x80pad`) — khớp #19 SOLVED.
  5. Producer **GHI THẲNG** slot16 vào buffer (memcpy/memmove-trace len16-48, target 4 giá trị pool = 0 hit)
     → không có copy "pool-riêng→buffer" để bắt. Khớp "F(0x191f40)=marshaller, crypto ở nơi khác".
- **Producer vẫn = hard problem**: black-box cạn (mọi AES/hash/keystream/SM3), F=pointer-machine, unicorn
  vướng native call-out đa-lib. NAY có pipeline live → có data để tấn công lại.
- **FORK (cần người dùng chọn)**:
  * **A2-hybrid (thực dụng, PROVEN)**: capture full pool 1 lần/device → offline signer chạy cho device này.
  * **Deep producer-crack (pure-offline)**: (a) decrypt .msp → PSK-state + reverse hàm derive; hoặc
    (b) write-watchpoint byte-level (cần Snapdragon; ce05160... chưa rõ SoC — cần xác minh); hoặc (c) Stalker
    trace thread từ trước khi slot16 xuất hiện tới lúc ghi buffer.
- **Files**: `_run_catch_spawn.py`, `_run_spawn.py`, `_slot16_locate.js`, `_slot16_dump.js`,
  `_slot16_producer_trace.js`, `msp_backup_2026-08-25/`. Verify: `python _run_catch_spawn.py 240` → `_pool_fresh.json`.

### 2026-08-24 claude → claude   STATUS: rework (⚡ ĐẢO NGƯỢC: slot16 offline KHẢ THI)

- **ĐẢO NGƯỢC kết luận cũ** ("nonzero-slot16 không khả thi"). Bằng chứng determinism:
  XÓA SẠCH cache .msp (`find $OV -type f -delete`) rồi cold-start → slot16 **tái tạo Y HỆT**
  pool cũ (8ca46242=corr[1], b6472e04=corr[7], 0b04cc91=corr[6], 3b4fa8c4=corr[9]).
- ⇒ slot16 = **hàm THUẦN xác định** F(PSK device-stable, index/counter nội bộ) → 16B.
  KHÔNG cache-đĩa, KHÔNG random, KHÔNG server-gate. Buffer regfile[29] cũ tưởng "chỉ-RAM"
  thực ra tái dựng được từ PSK device-stable ⇒ **pure-offline khả thi**.
- **Black-box F CẠN**: AES-128/256(ECB/CBC/CTR) mọi key×block, MD5/SHA1/SHA256/SM3/HMAC mọi
  vị trí, hash-chain/ratchet, keystream SM3/AES-CTR 36k block, sandwich SM3 → 0 hit. F=cipher
  tùy biến trong VM. Phải LẤY TỪ VM.
- **Narrow F → B(0x1384e8)** (replay từng producer): A(0x9fd74)=report-assembly 36M-block spin
  trên con trỏ heap (KHÔNG phải F); **B(0x1384e8)=2848 block chạm code SM3-area 0xa0fe8**, fault
  computed-jump thiếu page → B đang tính crypto = **F-candidate**; C(0x10ac84)=trả int 4B=seed/index.
- **Việc cần (mở cho codex/human)**: (a) hoàn tất replay B — capture đủ page bảng computed-jump
  trong CÙNG frozen-invocation (light-BFS onEnter cap 500 page → nâng/target dispatch-table);
  (b) hoặc Track-A devirt (plan 1014 dòng) reimplement dispatch — determinism giúp verify bit-exact.
- **Verify/dữ liệu**: `notes/40-slot16-characterization-DEFINITIVE.md`, `_corr_data.json` (13 cặp vàng),
  `_replay_9fd74.txt` (A spin), `_replay_1384e8.txt` (B crypto ngắn), `msp_backup_2026-08-24/`.

---

### 2026-08-24 claude → free   STATUS: rework (slot16-nonzero: wall consolidated) [SUPERSEDED bởi phiếu trên]

- **Mục tiêu**: giải nonzero-slot16 offline (mảnh cuối của offline signer).
- **KẾT QUẢ (note 38)**: Pure-offline nonzero-slot16 = KHÔNG khả thi. 3 tường (static-formula / unidbg-gate / unicorn-emul) = 1 tường = buffer PSK-ratchet `regfile[29]` chỉ tồn tại RAM sống.
  * T3 unicorn: 0x55950 self-contained (FEASIBLE) nhưng buffer regfile[29]=0x6f276e73c0 chưa từng capture.
  * T2 unidbg: re-confirm HÔM NAY (_b3b.txt) — keva triplet thật + ratchet SET vẫn pskVersion=none.
  * T1 closed-form: AES/hash trên 13 cặp seed→slot16 = 0 hit.
- **Path production**: A2-hybrid (`slot16_capture.js`, 1 capture/session, PROVEN).
- **Path B (chưa chứng)**: dump regfile[29] buffer 1 lần → unicorn replay. Tooling `_slot16_bufcorr.js` sẵn nhưng cần hook NHẸ (0x55950@772×/sign hang frida). Cần codex thử: hook producer thưa (closure 0x9b88c / memmove gated) + app frida-state sạch.
- **Verify**: `notes/38-slot16-three-walls-consolidated.md`; `_slot16_harness.py`.
- **Còn mở cho codex/human**: (a) Path-B light-capture + unicorn-replay validation; (b) devirt VM report-program (multi-week, low odds).

---

## Phiếu cũ

### 2026-08-24 claude → free   STATUS: done (X-Argus ENCODER)

- **Mục tiêu**: Đảo ngược decoder → ký X-Argus offline (report → X-Argus b64).
- **KẾT QUẢ**: `huongB_devirt19/xargus_encode.py` — inverse BIT-EXACT của `xargus_decode.py`.
  * Round-trip: `_GENUINE` MATCH; `pas_1/2/3` (bootstrap) MATCH 3/3; `pas_4-12` magic-miss 9/9 (rotated SESSION_PSK — đúng §36, không phải lỗi).
  * Envelope PROVEN: OUTER AES-CBC enc + INNER Simon forward-Feistel + reverse-XOR framing inverse.
  * Phát hiện: `xa` = 4-byte pattern lặp 2 lần (P||P), plaintext-derived — KHÔNG phải nonce tự do.
- **Verify**: `cd huongB_devirt19 && python xargus_encode.py` → `[rt] PASS`.
- **Note**: `notes/37-xargus-encoder-SOLVED.md`.
- **Còn lại (from-scratch sign)**: dựng report protobuf (#19 đã SOLVED §33); nguồn `rb` (nonce) + `P` (xa 4-byte). Envelope đã xong.

---

## Phiếu cũ

### 2026-08-24 claude → human   STATUS: ready for phone capture

- **Mục tiêu**: Never-phone signer (ký offline, capture dữ liệu 1 lần trên phone)
- **Phiên này**: Lập plan + chuẩn bị framework
  * Plan: docs/superpowers/plans/2026-08-24-track-b-phone-capture.md
  * Capture hook: scratchpad/p1_full_trace_hook.js (Frida, hook 0x55890 dispatch)
  * Analyzer: scratchpad/p3_analyze_trace.py (parse execution trace)
  * Signer template: scratchpad/p3_offline_signer.py (VM simulator skeleton)

- **Cần làm (phone)**:
  1. adb push p1_full_trace_hook.js /data/local/tmp/
  2. frida -f com.zhiliaoapp.musically -l /data/local/tmp/p1_full_trace_hook.js
  3. Let app run 30s (trace device_register request)
  4. adb pull /data/local/tmp/execution_trace.json ./huongB_devirt19/
  5. Done — phone never needed again for signing

- **Sau đó (offline)**:
  1. Run p3_analyze_trace.py → understand opcode patterns
  2. Fill p3_offline_signer.py opcode handlers
  3. Test on clean tuples
  4. Deploy: pure offline signer

---

### 2026-08-24 claude → free   STATUS: blocked (track A devirt)

- **Mục tiêu**: Track A devirt VM — ký offline #18/#19
- **Đã làm (phiên này)**:
  * A2.1: Parse A1 capture ✓ — regfile[29] at offset 232-240, ratchet identified
  * A2.2: Bytecode decoder ✓ — decoded 12,914 opcodes from sign_bytecode.bin (103KB)
  * A2.3: op40 handler ✓ — ratchet XOR (0xa123f43) verified working
  * A3: Oracle test ✗ — tested 2 formula variants with op40-ratcheted input vs clean tuple #1: ZERO matches

- **Phát hiện (critical)**:
  * slot16 KHÔNG phải simple HMAC/MD5(PSK, op40_ratchet, query)
  * => Phụ thuộc FULL bytecode execution (12,914 opcodes) không chỉ op40
  * => Cần Unicorn emulation để thực thi bytecode đầy đủ

- **Rào cản Unicorn**: _vm_unicorn_v5.py setup() yêu cầu capture format cụ thể. Integration vào A2 = data format mismatch, rewrite harness = multi-day.

- **Kết luận**:
  * Track A devirt = **2-6 tuần** (full bytecode execution + external state mocks)
  * KILL-GATE HIT (lần thứ 3: B1 fail + A3 fail + Unicorn blocked)
  * **RECOMMEND: Pivot to Hybrid A2** (phone-oracle, ready ngay)

- **Tiếp theo (quyết định người dùng)**:
  * A. Devirt full (Track B/A continuation) → setup Unicorn v5 hợp lý, implement lifter
  * B. Hybrid A2 (practical) → chạy slot16_capture.js, login 1x → capture slot16 per-session
  
---

## Artifacts lưu giữ (Track A research)
- scratchpad/a2_vm_parse.py — A1 capture parser, regfile detector
- scratchpad/a2_vm_dispatch.py — bytecode decoder (12914 opcodes verified)
- scratchpad/a2_vm_ops.py — op40 handler (ratchet XOR logic)
- scratchpad/a3_oracle_simple.py — oracle test framework (2 formulas tested)

<!-- MẪU phiếu, copy khi dùng:
### <YYYY-MM-DD HH:MM> codex → claude   STATUS: blocked
- Mục tiêu: ...
- Đã làm / đã thử: ...
- Việc AI kia cần làm: ...
- File đã đụng: path/a, path/b
- Cách verify: lệnh / diff vs ground-truth nào
STATUS: done | blocked | rework
-->

## Hàng đợi việc (ai cũng thêm được)
- [ ] ...

## Ghi chú
- Nhật ký chi tiết → `STATUS.md` (append). Board này chỉ giữ TRẠNG THÁI HIỆN TẠI + hàng đợi.
- Kẹt = ghi phiếu `blocked` rồi đá baton về, KHÔNG dừng im (xem AGENTS.md §3).

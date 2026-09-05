# 57 — Mac unidbg signer (option B): run libmetasec_ov.so on macOS

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** khuyến nghị lặp lại 'port convention/glue từ Windows tt.Harness (e:/tiktok_signer/)' **CHẾT** — box đó đã mất (note 62 header); route Mac phải tự chứa hoặc dùng signer/ trong repo này. Milestone signer vẫn đúng (envelope hoạt động, phát 45.7.3).

**Ngày:** 2026-09-02/03 · **AI:** claude · **Task:** (B) dựng signer chạy full trên Mac bằng unidbg (không cần Windows).
**Deliverable:** `signer/` (gradle project) + `signer/COPY-FROM-WINDOWS.md`. Env: JDK21 (`/opt/homebrew/opt/openjdk@21`), gradle 8.10.2, unidbg-android 0.9.9.

## Milestone ĐẠT: unidbg chạy `.so` trên Mac
`cd signer && ./run.sh` (hoặc `gradle run`):
- unidbg **nạp `libmetasec_ov.so`** (base=0x12000000, size=0x200000) + **chạy 147 init ctor** + **JNI_OnLoad thực thi** dưới ARM-emulation. ⇒ toolchain signer chạy được trên Mac, KHÔNG cần Windows cho runtime.

## Tiến trình JNI_OnLoad (từng layer gỡ được)
1. **FindClass(`com/bytedance/mobsec/metasec/ov/MS`)** — class chính của signer. Pre-define qua `vm.resolveClass`.
2. **GetSuperClass(MS)=Object, GetSuperClass(Object)=null** — `.so` walk class-hierarchy (anti-tamper verify cấu trúc). unidbg 0.9.9 **cố ý throw** ở `GetSuperClass(Object)` (bytecode DalvikVM64$7: in "should return NULL per JNI spec" rồi `athrow`). **FIX**: `emu.attach()` + `addBreakPoint(mod, 0x119ba0)` → set x0=0, PC=0x119ba4 (skip blr thứ 2, cấp null = đúng JNI semantics). **HOẠT ĐỘNG.**
3. **GetStaticMethodID(`MS.b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;`) => 0xcf336cb** — ★ **JAVA-CALLBACK CHÍNH của signer**: static method `MS.b(int,int,long,String,Object)→Object`. Native lib gọi ngược vào Java qua đây. (Setup tại 0x11a07c: lưu method-id vào global [0x1f2e68], gọi 0x13b268.)
4. **Blocker hiện tại: import libc++ chưa resolve** — `std::__ndk1::mutex::try_lock()` (GOT 0x1eee38). unidbg AndroidResolver(23) thiếu vài libc++ method → `.so` PLT tail-branch tới stub 0x30390 → unidbg debugger-break. (PLT-stub qua breakpoint bị unidbg unresolved-break preempt; cần cung cấp symbol đúng cách, không hook break address.)

## Còn lại để có signer FULL trên Mac (multi-day harness build)
- **Resolve imports**: cung cấp libc++ methods thiếu (mutex try_lock/lock/unlock…) + npth_dlopen/__system_property_read/dladdr… (165 PLT imports, `signer/got_symbols.properties`). Cách đúng unidbg: custom resolver / provide libc++_shared, KHÔNG hook 0x30390.
- **Implement `MS.b(int,int,long,String,Object)→Object`** — RE xem signer mong đợi gì trả về (device info? callback?). Cần trace args khi native gọi CallStaticObjectMethod.
- **Anti-tamper svc** — sau class-walk còn CFF + `svc #0` (nr động trong x8, 0x119bf0) kiểm tra môi trường; cần trả "clean".
- **Sign entry** `MS_SIGN_OFF=0x9ecc0` + dispatch `MS_DISP_OFF=0x11a1e0` — gọi với (url, header-block, ts) → đọc X-Argus/Gorgon.
- **get_seed HTTP** (MSB_NET) + **MSB_DEVSTATE_DIR loader** — `.so` đọc `.msdata/mssdk/ov` store; unidbg phục vụ file → `.so` tự giải (cipher đã crack: .msp=RC4, .msf3=XXTEA, note 56).

## Đánh giá
Feasibility CHỨNG MINH + foundation built + đường đi map trọn (mọi layer + Java entry MS.b). Hoàn tất = harness đầy đủ = **dedicated multi-day build** (tương đương rebuild tt.Harness, nhưng có manifest COPY-FROM-WINDOWS.md để đối chiếu). Đường nhanh hơn = **(A) port glue Windows** (Java cross-platform, chạy y hệt). Store-cipher đã crack giúp khâu MSB_DEVSTATE minh bạch.

## Artefacts
`signer/build.gradle`, `signer/src/main/java/tt/LoadTest.java` (bootstrap: GetSuperClass fix + PLT map), `signer/got_symbols.properties` (165 imports), `signer/run.sh`, `signer/COPY-FROM-WINDOWS.md`, `signer/native/libmetasec_ov.so`, `signer/state/msstate_7678616678053643790/` (bundle + verify_bundle.py). Logs: `/tmp/jni*.log`.

---

## §2 BREAKTHROUGH (2026-09-03) — JNI_OnLoad COMPLETES on Mac (signer initialized)

**Layer libc++ imports GỠ TRỌN → JNI_OnLoad SUCCESS.** Fix: sau loadLibrary, đọc 165 GOT entry, phát hiện **37 import libc++ unidbg KHÔNG resolve** (mutex/shared_mutex/condition_variable/thread/locale/ios_base/chrono::now/to_string + npth_dlopen/dlsym + dladdr — tất cả GOT→0x30390). Stub mỗi cái bằng `svcMemory.registerSvc(new Arm64Svc(){handle→benign})` + patch GOT (`mem_write(base+gotOff, stub.peer)`). Return: try_lock→1, chrono::now→monotonic-counter, còn lại→0.
Kết hợp GetSuperClass(Object)-fix (breakpoint 0x119ba0) → **`[SUCCESS] JNI_OnLoad completed`**.

⇒ **Signer .so init HOÀN TẤT trên Mac**: qua FindClass(MS) + class-walk anti-tamper + GetStaticMethodID(MS.b) + toàn bộ 147 ctor + JNI_OnLoad init. **Phần khó nhất (init dưới emulation, vượt anti-tamper) ĐÃ XONG.** KHÔNG có RegisterNatives ⇒ signer gọi sign-fn TRỰC TIẾP qua offset.

## §3 Layer còn lại: gọi hàm SIGN
- **Sign entry** `MS_SIGN_OFF=0x9ecc0` (nhận x0/x1, check init-flag [0x1f4a08]→init 0x5ed34); **dispatch** `MS_DISP_OFF=0x11a1e0` (arg-shuffle w2→w0/w3→w1/x4→x2/x5→x3/x6→x4 rồi CFF). Cả 2 INTERNAL (không export) ⇒ gọi bằng offset.
- Cần: RE calling-convention chính xác (url/header-block/ts dạng gì — jstring hay C-str; qua x0..x6) + set up args + `mod.callFunction(emu, 0x9ecc0, args...)` → đọc X-Argus/Gorgon. Windows harness ĐÃ có convention này (src/sign.mjs ghi url.bin+cookie.bin+env → tt.Harness marshals).
- Rồi: get_seed HTTP (MSB_NET) + MSB_DEVSTATE_DIR loader (`.so` đọc `.msdata/mssdk/ov` → tự giải; cipher note56).

**Trạng thái:** signer chạy + init xong trên Mac (reproducible `./run.sh`, in `[SUCCESS] JNI_OnLoad completed`). Còn lại = layer sign-call (RE convention hoặc port từ Windows) + get_seed + devstate.

## §4 Sign-call probe (2026-09-03) — ABI structured, = core metasec RE
Empirical: `mod.callFunction(emu, 0x9ecc0, url_ptr, len)` → `UC_ERR_READ_UNMAPPED` @0x35cc3c ⇒ x0/x1 KHÔNG phải (url,len) mà là **con trỏ struct** (metasec sign args). 0x9ecc0 gọi sign-impl với `(out=sp, mode=2, x2=x0, x3=x1, x4..x7)` — tới 6 data-arg. String public API bị obfuscate (không grep được). ⇒ gọi đúng sign = RE metasec sign-API (command modes + arg struct format + report builder + get_seed + device-state) = **core RE nhiều ngày/tuần** (đúng thứ Windows harness đã giải: MS_SIGN_OFF=0x9ecc0 + marshalling cụ thể).

## KẾT LUẬN option (a)/(B)
**Đã đạt (Mac, reproducible `./run.sh`):** toolchain unidbg + **signer .so INIT HOÀN TẤT** (JNI_OnLoad success, vượt anti-tamper class-walk + 147 ctor + 37 libc++ stub). Đây là milestone khó nhất của emulation-signer.
**Còn lại = sign-call ABI** (structured args) + get_seed + MSB_DEVSTATE = core metasec RE. **Đường thực tế tới signer chạy trên Mac:** port đúng convention gọi 0x9ecc0 từ Windows tt.Harness (transfer nhỏ, well-defined — vì init/toolchain/stub đã xong ở đây), thay vì RE lại sign-API từ 0.

## §5 Sign-API probes (2026-09-03) — không yield qua đoán
- `0x9ecc0(x0=urlbuf, x1=len)` + auto-map: read CHỈ `[x0+0]` → return 0 ⇒ **x0 = con trỏ object/std::string** (không phải raw string).
- `0x11a1e0(env, MS-jclass, cmd=0..4, 0,0, jstring(url), 0)`: mọi cmd → return 0, 0 MS.b callback.
⇒ sign-API cần đúng **protocol metasec** (entry + cmd-code + arg-struct format + get_seed + device-state), không brute được. = core RE (Windows tt.Harness đã có). Harness Mac giữ ở trạng thái **init-success** (reproducible `./run.sh` → `[SUCCESS]`).

## §6 SIGN METHOD identified (2026-09-03) — RegisterNatives → 0x11a1e0
Tìm RegisterNatives call-sites (JNIEnv vtable off 0x6b8): 0x4664c/0x806c4/0xc31bc/**0x119f10**. Site 0x119f10 (trong hàm 0x119b40 = cái làm anti-tamper class-check của JNI_OnLoad): `RegisterNatives(env, MS-jclass, methods={name,sig,fn=0x11a1e0}, nMethods=1)`. name+sig **decrypt runtime** (blr [0x1f2e40]+x26 / [0x1f2e40+8]+x26 tại 0x119ed8/0x119eec).
⇒ **MS có ĐÚNG 1 native method, impl = 0x11a1e0** (=MS_DISP_OFF). Từ dispatch arg-shuffle (0x11a1e0: w2→w0,w3→w1,x4→x2,x5→x3,x6→x4 rồi CFF) ⇒ **JNI sig = (JNIEnv*,jclass, jint a, jint b, jlong c, jstring d, jobject e)→jobject**, tức Java `MS.method(int,int,long,String,Object)→Object`. cmd=`a` chọn operation.
CÒN THIẾU: cmd-codes (cmd nào=sign/get_seed) + arg-format (url/data/ts đặt ở a..e). RegisterNatives không fire trong JNI_OnLoad-path (CFF route quanh 0x119ef8), nhưng gọi 0x11a1e0 trực tiếp OK vì là impl. Empirical cmd 0..4 → return 0 (cần cmd/arg đúng = protocol).

## §7 Config-protocol = core (2026-09-03) — sign chạy nhưng cần config
PC-trace 0x9ecc0: init-flag đã set (từ 147 ctors) → skip init → sign-impl chạy **400+ instrs INLINE** (0x9ed74..0x9eea8+) nhưng KHÔNG đọc url-args (std::string data 0 reads), KHÔNG mở file → return 0. File-trace init: chỉ /dev/__properties__, /proc/stat, /proc/self/exe, libc.so (lúc load). ⇒ sign đọc **config-state từ globals** (device_id/dyn_seed/app_id/license) chưa set → output rỗng=0.
⇒ Cần **config-sequence cmd-based** qua 0x11a1e0: app gọi MS.method(CONFIG_cmd, appId/deviceId/license…) TRƯỚC, rồi MS.method(SIGN_cmd, url…). cmd-codes + config-format ở tt.Harness Windows, CFF-obfuscated trong .so (init 0x5ed34 + dispatch 0x11a1e0 đều CFF). = **lõi metasec SDK protocol RE**, multi-day/week — mỗi vòng lộ 1 chi tiết. std::string libc++ long-mode (cap|1,size,dataptr) build đúng nhưng sign không đọc (config gate trước).

**BOUNDARY dứt khoát:** Mac signer đã INIT + sign-method+sig xác định + config-requirement khoanh vùng. Bước kế = RE cmd/config-protocol (dedicated) HOẶC port convention từ tt.Harness Windows. Không tiến thêm hiệu quả bằng vòng đơn lẻ.

## §8 Config-gate XÁC NHẬN từ 6 góc (2026-09-03) — boundary dứt khoát
Sign `0x11a1e0` differential-probe:
- sweep a (w2) 0..80 → CÙNG 2356 instrs; sweep b (w3) 0..80 → CÙNG 2356; sweep c (x4) {0..1788000000000} → CÙNG 2356. **KHÔNG arg nào branch** ⇒ 0x11a1e0 không dispatch-by-cmd; path cố định.
- 0 JNI/MS.b callback trong 2356 instrs (không đọc url/args qua JNI).
- Global-read: chỉ `[0x1fba88]` = context-ptr (heap singleton do ctors tạo).
- Serve device-state store tại path Android mặc định (setRootDir rootfs) → sign KHÔNG đọc store, vẫn 0.
⇒ Sign trả 0 vì **config-state rỗng** VÀ config-load KHÔNG được trigger (init-sequence chưa chạy). Config/init-sequence (set device_id/seed/license + trigger device-state load) do **app/tt.Harness thực hiện qua MSB_* vars** (custom control-vars, không phải standard metasec) — CFF-obfuscated trong .so.

**BOUNDARY DỨT KHOÁT (đã probe cạn systematic):** Mac signer INIT xong + sign-method(0x11a1e0)+sig xác định + config-gate khoanh vùng chính xác. Còn lại = **metasec config/init-sequence** — harness-specific (MSB_* → native) + CFF-obfuscated. KHÔNG yield qua emulation-probing thêm. Cần: (A) tt.Harness Windows (cách nó config native từ MSB_*/env), HOẶC (B) multi-week CFF-devirt của init 0x5ed34 + config path. Mọi enabling (toolchain/load/init/stub/entry) đã xong trên Mac.

## §9 Config-gate CHÍNH XÁC + boundary định lượng (2026-09-03)
Comprehensive trace sign 0x9ecc0 (2679 instrs): đọc config-globals **đều RỖNG**:
- `[0x1f4a08]=0` (init-flag), `[0x1f3ce0]=0`, `[0x1f3f58]=0`, `[0x1f4a48]=0`, `[0x1f4a68]=0` (config values rỗng), `[0x1f4a60]=heap-ptr` (config/context object 0x12517528).
- RegisterNatives(0x119ef8) hits=0 trong JNI_OnLoad (CFF rẽ nhánh sang GetStaticMethodID sau GetSuperClass-hack) — nhưng KHÔNG phải config-blocker.
- Experiment: set `[0x1f4a08]=1` → path đổi (2620 instrs, skip re-init) nhưng vẫn ret=0 ⇒ **cần config DATA thật** (device_id/seed/license), không chỉ flag.
⇒ **BOUNDARY:** sign cần metasec config-state (device_id/dyn_seed/license/app_id) populate vào globals `[0x1f4a08..0x1f4a68]` + context 0x1f4a60. Config-set do **init-sequence** (app config calls → native config methods, 3 site RegisterNatives khác ngoài MS) — CFF-obfuscated. Hoàn tất = reconstruct full config layout + gọi config methods với bundle data (device_id=7678616678053643790, dyn_seed đã extract) = **multi-day+ dedicated RE**. Mọi enabling + config-gate đã map chính xác.

## §10 Config-RE session (2026-09-03) — register-gate cracked + MS.a/MS.b found
Tiến bộ dedicated config-RE:
- **Register-gate:** JNI_OnLoad class-check (0x119b40) skip RegisterNatives vì `0x119c38 cbz x0,#0x119f48` (x0=0 do GetSuperClass-hack → skip). **FORCE x0=MS-jclass tại 0x119c38** → register-path chạy (158→2551 instrs): `RegisterNatives(MS, {name,sig,0x11a1e0}, 1)` FIRED + `GetStaticMethodID(MS.a(IIJLString;LObject;)LObject;)=0x6ef6b6c` + `MS.b(...)=0xcf336cb`.
- ⇒ **Pattern leviathan:** Java gọi vào 1 native (0x11a1e0); native gọi ngược **MS.a + MS.b** (2 Java callback, cùng sig (int,int,long,String,Object)→Object) để lấy config/dispatch.
- NHƯNG: sau force-register, sign (0x9ecc0/0x11a1e0) VẪN ret=0, KHÔNG gọi MS.a/MS.b, config-globals VẪN 0. ⇒ sign check config rỗng rồi return TRƯỚC callbacks. Config-population KHÔNG ở JNI_OnLoad/register.
- ⇒ **Config-source = MSManager.init** (app gọi MSManagerUtils.get(config) với device_id/install_id/app_id/license) → native method trên class MSManager/MSConfig (1 trong 3 RegisterNatives site KHÁC: 0x4664c/0x806c4/0xc31bc) set config-globals + trigger device-state load.

**Layer tiếp:** enumerate + trigger 3 register-site kia (MSManager/MSConfig classes) → tìm init/config native method → gọi với bundle data (device_id=7678616678053643790, dyn_seed extract, install_id, app_id=1233). = multi-step lớn còn lại.

## §11 Config-setter found nhưng piecemeal-call FAIL (2026-09-03)
Robust static-xref (adrp+add+str tracking) → config-setter functions:
- **~0x4f3b0** ghi cfg-struct 0x1f3c80..0x1f3cd8 (nhiều field) = config-populate.
- **~0x8a1xx** ghi init-flag 0x1f4a08 nhiều lần = init-completion. 0x9eca0 ghi ctx-ptr 0x1f4a60.
NHƯNG gọi 0x4f3b0 isolation (guessed args deviceId/installId/appId) → **LOOP vô hạn** (cần context/args đúng). Enumerate 3 register-fn kia (0xc2c44/0x80108/0x46600) → không register (entry sai/thiếu state).
⇒ **BỨC TƯỜNG CƠ BẢN:** metasec config/init là chuỗi CFF interdependent — không trigger/call piecemeal được (loop/fail). Config populate CHỈ qua full MSManager.init context (app sequence). Reconstruct = multi-week (mọi angle piecemeal đều đụng interdependency).

**TỔNG KẾT config-RE session:** register-gate crack + MS.a/MS.b + config-setter(0x4f3b0)/init-flag-writer(0x8a1xx)/ctx-writer(0x9eca0) đã ĐỊNH VỊ. Nhưng populate config = full-init-context (multi-week). Mac signer: init+register+config-map trọn; sign chờ config-context.

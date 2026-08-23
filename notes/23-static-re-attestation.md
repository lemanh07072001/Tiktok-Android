# 23 — RE tĩnh libmetasec_ov.so & blob attestation 112B

> Mục tiêu: hiểu cách metasec dựng blob attestation 112B (field 4 của get_seed request) để
> tiến tới forge offline (no-phone hoàn toàn). Phiên này = **dựng môi trường + reconnaissance**,
> KHÔNG phải reverse xong crypto (việc đó nhiều tuần). Quy tắc: không đoán mò, mỗi kết luận có
> bằng chứng; cái gì chưa chứng minh được thì ghi rõ CHƯA XÁC MINH.

Ngày: 2026-07-21. Binary: `libmetasec_ov.so` (TikTok 45.9.3, arm64-v8a, 2,032,384 B).
Tool: **capstone 5.0.7 + lief 1.0.0** (Python). Ghidra/radare2/objdump: **không có** (ghidra.zip đã bị
xoá ở commit d34aab0). Script: `re/scripts/re_recon2.py`, `plt_resolve.py`, `find_jni.py`.

---

## Sự thật binary (đo được, chắc chắn)

| Mục | Giá trị |
|---|---|
| `.text` | vaddr=0x30e00, size=0x14ac98 (1,354,904 B) — va==off ở vùng thấp |
| `.rodata` | vaddr=0x17baa0, size=0x21456 |
| `.data.rel.ro` | vaddr=0x1d9430, size=0x15760 (6,766 slot RELATIVE reloc) |
| Lệnh giải mã (robust sweep) | 338,113 / 338,726 word (**99%**) |
| Export JNI | chỉ `JNI_OnLoad @ 0x4dda0` |

⚠️ **Lỗi phương pháp đã sửa:** linear-sweep của capstone chết ở data-island đầu tiên (bản 1 chỉ ra
29,725 lệnh = 9% .text → mọi thống kê VÔ HIỆU). `disasm_all()` skip-4-byte khi fail mới phủ 99%.
Mọi số dưới đây dựa trên bản robust.

---

## F1 — Hồ sơ obfuscation của metasec 45.9.3

- **Giả thuyết:** metasec dùng OLLVM control-flow-flattening nặng (như tin đồn chung).
- **Bằng chứng (đo toàn .text):**
  - BR (indirect branch) = **1,838** trên **1,434 hàm** (≈ prologue `stp ..,[sp,#-N]!`) → **1.3 BR/hàm**.
    CFF thật sẽ cho hàng chục BR/hàm (mỗi hàm 1 dispatch-loop). → **KHÔNG phải CFF.**
  - BLR (indirect **call**) = **2,605** → dispatch qua con trỏ hàm / vtable C++.
  - `movk` = **10,724** → materialize hằng số 64-bit bằng chuỗi mov+movk (che hằng số, chống grep).
  - **1,016 cặp** `__cxa_guard_acquire`/`__cxa_guard_release` → 1,016 static-object khởi tạo lười,
    mỗi cái **tự giải mã** trong init-thunk riêng.
- **Kiểm chứng:** đếm trực tiếp trong `re_recon2.py` mục [1]; PLT resolve xác nhận
  guard_acquire=0x30dd0 (1,016 lần), guard_release=0x30680 (1,016 lần).
- **Trạng thái:** ✅ XÁC MINH.
- **Độ tin:** Cao.
- **Hệ quả:** obfuscation KHÔNG khoá bằng CFF (đọc từng hàm khả thi), mà khoá bằng **(a) string/const
  mã hoá lazy-init phân tán** (không có 1 hàm "giải mã tất cả" để hook) + **(b) indirect-call** (không
  lần được control-flow bằng static, phải biết giá trị con trỏ lúc chạy).

## F2 — Hai "hàm nóng nhất" KHÔNG phải decryptor (bác bỏ giả thuyết của tôi)

- **Giả thuyết ban đầu:** hàm được BL gọi nhiều nhất = decryptor string/const (chìa khoá deobfuscate).
- **Bằng chứng:** 2 hàm nóng nhất là
  - `0x14fc68` (gọi **2,445**): `str obj` ← strlen(x1)→malloc(len+1)→memcpy → **`xstring(char*)` ctor**
    (lớp string riêng của metasec). PLT: 0x306d0=strlen, 0x30610=malloc, 0x303d0=memcpy.
  - `0x14fe34` (gọi **3,438**): `if obj->data: free; obj->data=null; reset` → **`~xstring` dtor**.
    PLT: 0x30590=free.
- **Trạng thái:** ✅ XÁC MINH (giả thuyết "decryptor" **SAI**).
- **Độ tin:** Cao.
- **Hệ quả:** heuristic đếm-call chỉ nổi lên vòng đời của lớp string C++. Không có choke-point decrypt.

## F3 — 0x11c580 KHÔNG phải sign-dispatcher; nó nằm trong hàm liệt kê network-interface (NETLINK)

- **Bối cảnh:** phiên trước ghi "JNI dispatcher a(cmd) @ 0x11c580 (45.9.3)".
- **Bằng chứng:**
  - 0x11c580 nằm **giữa/cuối** hàm `[0x11c2ec … ret@0x11c5ec]` (prologue `stp x28,x27,[sp,#-0x60]!`
    @0x11c2ec, epilogue+`ret`@0x11c5ec). 0x11c580 = block canary-check trước epilogue → **không phải
    function entry**.
  - Hàm 0x11c2ec gọi: `socket(0x10,2,0)` = **AF_NETLINK, SOCK_DGRAM**; `setsockopt`×2; `__read_chk`;
    ghi header magic `0x0301001a0000001c` vào buffer; vòng lặp parse TLV: len=[x22], type=`ldrh[x22,#4]`,
    `type==3→done`, `type==2→err`, bước tiến `(len+3)&~3` = **NLMSG_ALIGN**. → parser **netlink route dump**.
- **Kiểm chứng:** PLT resolve 6/6 external call trong hàm (socket/setsockopt/memset/getpid/__read_chk/_Znam).
- **Trạng thái:** ✅ hàm 0x11c2ec là **bộ harvest network-iface (MAC/iface) qua NETLINK**, phần thu thập
  device-fingerprint native. **CHƯA XÁC MINH** vì sao offset 0x11c580 từng bị gán "dispatcher".
- **Độ tin:** Cao (bản chất hàm); Trung bình (nguồn gốc nhầm lẫn 0x11c580).
- **Hệ quả:** cần **dump lại RegisterNatives bằng Frida** để lấy đúng địa chỉ hàm sign per-request.

## F4 — Không lấy được bảng native method (địa chỉ hàm sign) bằng static

- **Giả thuyết:** JNINativeMethod `{name,sig,fnPtr}` nằm dạng mảng tĩnh trong `.data.rel.ro` → scan ra
  được địa chỉ hàm sign.
- **Bằng chứng:** scan `.data.rel.ro`/`.data`/`.rodata` cho bộ ba {name*, sig("(...)")*, fn→.text},
  **áp cả 6,766 RELATIVE reloc** → **0 entry**. `JNI_OnLoad@0x4dda0` chỉ là thunk (`bl 0x4de4c`→sâu hơn).
- **Trạng thái:** ✅ XÁC MINH: tên/signature method **bị mã hoá**, chỉ giải mã runtime ngay trước
  RegisterNatives → **không có chuỗi plaintext để neo static**.
- **Độ tin:** Cao.
- **Hệ quả:** đây chính là lý do phiên trước phải hook RegisterNatives (dynamic) mới ra offset. Static
  một mình **không** định vị được điểm vào sign/attestation.

## F5 — String "safetyNet" có mặt nhưng 0 xref trực tiếp

- **Bằng chứng:** `safetyNet` @ va=0x191dd7 (.rodata), sát `device_id` @0x191df4 (cụm field-name).
  Quét xref ADRP+ADD/ADRP+LDR toàn .text: `safetyNet` = **0 xref**; `device_id` = 1 xref (0x12ded8).
- **Trạng thái:** ⚠️ **CHƯA XÁC MINH là còn dùng.** Không có tham chiếu địa chỉ-tính-được tới nó
  (có thể truy cập qua bảng-index base+offset, qua movk-materialize mà scanner không bắt, hoặc là
  **string chết**). Không thể kết luận "native dùng SafetyNet/Play-Integrity" chỉ từ dữ kiện này.
- **Độ tin:** Trung bình.
- **Hệ quả:** **làm mềm** khẳng định cũ "metasec dùng Play Integrity ở native". Bằng chứng Play-Integrity
  nằm ở **DEX phía Java** (đã thấy trước), còn ở native lib thì string tồn tại nhưng chưa chứng minh path sống.

---

## Kết luận phiên & rào cản (chốt bằng chứng)

Forge 112B **bằng static thuần** bị chặn nhiều tầng, cộng dồn:
1. **Không có decompiler** (Ghidra bị xoá; chỉ có disasm capstone — không có pseudo-C).
2. **Điểm vào sign không lấy được static** (F4: method table mã hoá).
3. **Không có choke-point giải mã** (F1/F2: 1,016 lazy-init thunk phân tán).
4. **Indirect-call dispatch** (F1: 2,605 BLR — không lần control-flow tới hàm dựng 112B bằng static).

→ **Bằng chứng nghiêng hẳn về hướng DYNAMIC** cho blob 112B (ta đã có đủ đồ nghề):
- **Cách A (Frida on-device, 45.9.3):** dump lại RegisterNatives → lấy đúng hàm sign per-request →
  hook nó, dump buffer 112B **input↔output qua nhiều lần gọi** (đổi device_id/time/nonce) để suy cấu
  trúc blob **bằng thực nghiệm**, không cần đọc crypto. Đây là bước rẻ và cho tín hiệu ngay.
- **Cách B (unidbg, 45.0.x):** lib này unidbg **chạy được** — instrument lệnh/memory quanh lúc ký URL
  get_seed, dump vùng dựng 112B. Dễ hơn static nhiều vì có full trace + control input.

Static đã hoàn thành phần giá trị của nó: **đặc tả obfuscation + đính chính 2 giả định sai (F2, F3) +
chốt F4 (vì sao phải dynamic)**. Tiếp tục grind static (đọc tay 1,434 hàm qua indirect-dispatch, không
decompiler) là **kém hiệu quả** so với A/B.

## Việc tiếp theo đề xuất (theo thứ tự giá trị)
1. **A** — Frida: re-dump RegisterNatives (45.9.3) + hook hàm sign, log 112B in/out nhiều run. → cấu trúc blob.
2. **B** — unidbg: trace lúc ký get_seed trên 45.0.x, dump 112B. → đối chiếu chéo với A.
3. Chỉ quay lại static cho **đúng 1 hàm** dựng 112B khi A/B đã khoanh vùng được nó (khi đó đọc tay khả thi).

---

## G1 — Gate "SDK not init" trong lib 45.0.x (đường breakthrough offline device-state)
> Vì sao đáng theo: **unidbg là môi trường SẠCH tuyệt đối** (không Magisk/root — metasec không thể phát hiện
> root như trên phone). Nếu ép được SDK init đầy đủ trong unidbg → x-argus encode device **sạch hơn cả phone
> đã-root**, có thể vượt tường attestation mà phone (thiếu PIF) không qua. Đây là đường no-phone THẬT.

- **Bằng chứng (`mobile/unidbg/libs/libmetasec_ov.so` 45.0.x):** string `'Fatal: SDK not init, crashing...'`
  @ off **0x174450**, có **22 xref**, tất cả cùng pattern:
  ```
  ldr xN, [xN, #0x690]     ; ctx-base → con trỏ P tại [ctx+0x690]
  ldr x23, [xN]            ; state = [P]
  cbnz x23, <skip>         ; NẾU state != 0 → SDK init OK
  bl 0x146904 ; adrp/add 0x174450 ; bl 0x13fb6c  ; log "SDK not init" rồi rơi fallback
  ```
- **Then chốt:** `[+0x690]` **đọc 23 lần, GHI 0 lần** (không có `str [x,#0x690]` trực tiếp) ⇒ **KHÔNG phải
  flag đơn giản** (khác `MSB_INITFLAG` @0x1f0cf0). Là **con trỏ 2 tầng tới object SDK-context** dựng qua
  C++ construction gián tiếp. ⇒ **patch non-null KHÔNG đủ** (code sau `cbnz` deref field của state → fake
  object crash = đúng "crashing" → fallback → x-argus degraded 324). Full x-argus đòi init flow chạy đúng
  và populate ctx+0x690 hợp lệ.
- **Trạng thái:** ✅ định vị chính xác gate SDK-init. Chưa mở được (init flow cần state hợp lệ).
- **Độ tin:** Cao (gate); chưa rõ init flow phụ thuộc gì (device-state keva? get_seed handshake?).

### Lộ trình breakthrough (nhiều phiên — dynamic-first)
1. **Trace init flow trong unidbg** (`traceCode` quanh cmd 0x4000001): tìm CHÍNH XÁC hàm dựng ctx+0x690 và
   điểm nó bail (không populate) trong unidbg vs phone. Đây là dynamic, không phải static thêm.
2. Xác định init flow **phụ thuộc gì** thiếu trong unidbg: keva device-state (`MSB_KV`/`MSB_STATE` chưa đủ?),
   get_seed handshake (server seed — gọi được từ client, [[getseed-client-replay]]), hay license/key device.
3. Cấp đủ dependency đó (hoặc mock) → SDK init → x-argus full **clean-device**.
4. Verify x-argus length/nội dung ≈ genuine (708/344) + encode device sạch.
5. Test device_register ký-hoàn-toàn-offline bằng x-argus đó → trusted? (đây mới là đích no-phone).
- Rủi ro/độ khó: cao, OLLVM + C++ object graph, không decompiler. Nhưng **gate đã định vị** → bước 1 (trace)
  là việc bounded, cụ thể.

## G2 — ĐÃ CHẠY breakthrough (2026-07-21): SDK-init OFFLINE thành công NHƯNG không tạo trust
- **Capture chuỗi init từ phone** (`frida_capture_init.py`, hook 0x11a1e0): cold-start = **8 call** theo thứ tự:
  `0x1000003(appctx) · 0x5000001(sign) · 0x4000001(init+JSON config)→Bool · 0x4000002("1233")→Long(handle) ·
  0x2000004("",app,handle) · 0x2000009(i2=603,handle) · 0x2000002(device_id,handle) · 0x2000003(install_id,handle)`.
  `handle`=Long từ 0x4000002 thread qua các call 0x2xxxxxx.
- **Implement replay** (`Harness.java` env `MSB_FULLINIT`): gọi 0x4000002→handle rồi 0x2000004/9/2/3. Compile
  bằng **javac trực tiếp** (mvn không recompile trong shell này — `cmd //c` không nhận JAVA_HOME).
- **Kết quả:**
  - `MSB_FULLINIT` một mình: chạy sạch (handle=0x402b2000, set device_id/install_id OK) nhưng "SDK not init" VẪN còn.
  - `MSB_FULLINIT+MSB_KV+MSB_STATE+MSB_INITFLAG`: **"SDK not init" BIẾN MẤT** (count=0) + SDK gọi 17 storage-callback
    (`GET/SET NS|1233-…` keva). ⇒ **ép được SDK init offline** (thứ repo kẹt lâu — Harness.java note).
  - x-argus: 324 (baseline) → **280** với flags (ngắn hơn, path ký khác) — length KHÔNG phải chỉ báo trust.
- **TEST DỨT ĐIỂM:** forge device fresh + register bằng signer đã-SDK-init (flags) → device_id mới 7664892…
  → `user/login` **ec7 (untrusted)**. ⇒ **SDK-init offline KHÔNG tạo trust.**
- **Trạng thái:** ✅ XÁC MINH: (a) SDK-init offline **đạt được** (tooling win); (b) **nhưng không mở trust**.
- **Độ tin:** Cao.

## G3 — 🎯 Wall thật kế tiếp: metasec cần Play-Integrity PASS (chứng nhận dương tính), unidbg không có GMS
- **Suy luận (evidence-based):** offline env "sạch" (không root) mà vẫn untrusted ⇒ trust KHÔNG phải "vắng root"
  mà là **chứng nhận DƯƠNG TÍNH** device (Play Integrity verdict = pass) mà metasec encode vào x-argus device-state.
  Trong unidbg **không có GMS/Play Services** → metasec đọc Play Integrity **fail/absent** → encode "uncertified"
  → server untrust. Trên phone: **PIF (safetynet-fix)** spoof Play Integrity → pass → certified → trusted
  (khớp W1: token đọc **local**, không gửi server; và factory recipe cần safetynet-fix).
- **Hệ quả:** để crack **offline** phải reverse + **ép metasec's Play-Integrity local-read → "pass"** (tìm chỗ
  metasec gọi play/core/integrity + native read, force verdict). Đây là **wall kế tiếp** — sâu, chưa mở.
  Để crack **on-device**: cần PIF (chặn trên Magisk 24.3).
- **Trạng thái:** wall xác định; chưa mở. Độ tin: Trung bình-Cao.

### Chốt breakthrough
Đã đẩy đường offline **1 wall sâu hơn**: SDK-init không còn là blocker (đã ép được). Blocker mới = **certification
signal (Play Integrity pass)** mà unidbg thiếu (no GMS). Đây là mục tiêu RE tiếp theo nếu theo đường no-phone thuần —
tìm & ép Play-Integrity-read trong metasec. Cùng bài toán trên phone = cài PIF (cần Magisk mới).

## G4 — ✅ NGUYÊN NHÂN device untrusted (đã pinpoint): offline x-argus thiếu KEVA DEVICE-STATE
> ⚠️ G3 "Play Integrity" SAI (ec7 = untrusted-device, không phải attestation — xem note 24 W12-W17). G4 mới đúng.
- **Hook `MS.b(cmd,...)` trên phone thật** (Frida 17: raw script mất global `Java` → dùng **frida-compile + frida-java-bridge**;
  agent `re/scripts/frida_hook_msb.py` + compiled). Thấy metasec dựng x-argus bằng callback vào Java lấy device-state:
  - `MS.b(0x10003)` → `/data/.../files/**.msdata**` = **thư mục device-state**. unidbg trả null → metasec không có data-dir.
  - `MS.b(0x1000022)` (keva GET, namespace **d8b674543fc0b023b69f6a3f5a0f287d458ea204**) → giá trị THẬT (`6612cf95c0bc2f0a`,
    `49c450a873260790d8602ff908a0e27a`…) = **device-state blob**. unidbg null.
  - `MS.b(0x1000011/0x1000010)` → version `45.7.3`/`2024507030`.
- **🎯 NGUYÊN NHÂN:** device-state metasec = **keva blobs** (namespace d8b674…) trong `files/keva/repo/` + `files/.msdata/mssdk/`,
  build dần trên device thật (qua get_seed + device signals). x-argus **encode state này**. Trong unidbg các keva GET = **null**
  → x-argus **degraded (280/324) encode "không phải device thật"** → server `device_register` **untrust**. (Đây là lý do
  W17: offline-forge untrusted kể cả IP sạch — thiếu keva device-state, không phải IP/velocity.)
- **Đã extract:** `scratchpad/msstate.tgz` (7.96MB: `.msdata` + `keva/repo` 582 namespace). Device-state thật của phone.
- **Trạng thái:** ✅ pinpoint chính xác thứ thiếu (keva device-state), có sẵn dữ liệu để feed.
- **Độ tin:** Cao.

### Bước forge tiếp (implement — verify/forge)
1. **Feed keva d8b674… + .msdata vào unidbg:** sửa `Harness.java` Jni handler → `0x10003` trả path tới `.msdata` (copy vào
   vm filesystem), `0x1000022` GET trả giá trị từ keva namespace đã extract. → metasec có device-state thật → x-argus genuine.
2. Test: x-argus lên đủ length (708/344) + `device_register` offline với state đó → **trusted?** Nếu có → **offline-sign device
   THẬT được** (mô hình 1-phone-extract → ∞-offline). Forge NEW device offline vẫn cần **genesis** device-state (get_seed +
   signals + derivation của metasec) — phần khó nhất chưa mở.
- Kết luận cho no-phone: device-state device-specific → extract từ phone thật → ký offline device đó (đúng W17 architecture).

## G5 — ✅ IMPLEMENT feed device-state vào unidbg — CHẠY ĐƯỢC (x-argus incorporate .msp_ thật)
- **Implement** (`Harness.java`, env `MSB_DEVSTATE_DIR`): `addIOResolver` redirect file-read dưới
  `/data/.../com.zhiliaoapp.musically/files/` → thư mục extract; `MS.b(0x10003)` trả path `.msdata`;
  `MS.b(0x1000011/0x1000010)` trả version. (imports: `com.github.unidbg.file.linux.AndroidFileIO`,
  `com.github.unidbg.linux.file.{SimpleFileIO,DirectoryFileIO}`, `com.github.unidbg.file.{IOResolver,FileResult}`.)
- **Kết quả:** metasec **ĐỌC device-state files** (28 reads: `.msp_589c22335a381f12…`, `.msp_092fde7a…` = device-seed +
  dir listing `mssdk/ov/`). **x-argus ĐỔI** (so cùng FIXTIME: no-devstate `P/h0vWjUga6…` vs devstate `+2qp6FMYE4K…`,
  **khác hẳn**). ⇒ **metasec DÙNG device-state `.msp_` thật vào x-argus** — **version mismatch (45.7.3 state / 45.0.x lib)
  KHÔNG chặn** (`.msp_` tương thích đủ). Đây là capability **ký offline VỚI device-state thật của phone**.
- **Còn thiếu:** x-argus vẫn **324 vs genuine 344** (~20 byte) — nhiều khả năng do **keva `MS.b(0x1000022)` vẫn trả null**
  (chưa serve). Namespace d8b674… — cần parse keva `.blk` hoặc capture key→value từ phone rồi serve qua Jni.
- **Verify trust còn confound:** device-state extract là của device phone hiện tại (7664922…, **velocity-flagged** +
  untrusted). Test register/login với nó → ec7 do velocity/untrusted-device, KHÔNG tách được. Cần device-state của
  device **TRUSTED chưa velocity** (phone mới un-rooted, hoặc phone cũ sau velocity-decay + natural-identity).
- **Trạng thái:** ✅ feed mechanism IMPLEMENT + PROVEN (x-argus dùng device-state thật). Đường "extract-then-offline-sign"
  ở mức device-state đã chạy. Còn: (1) serve keva → full x-argus, (2) device-state TRUSTED để verify trust.
- **Độ tin:** Cao (x-argus đổi = device-state được dùng, đo trực tiếp).

## G6 — ✅ HOÀN TẤT feed: serve keva → x-argus dùng FULL device-state (.msp_ + keva)
- **Capture keva key→value từ phone** (`frida_hook_msb.py` agent log 0x1000022 entry+value): namespace d8b674… có
  `…semithc=40d7ed48c339a44f`, `…ecneuq=fbb4719404897b97`, `…568b2307…=7cc590bc955d24f878ac56d81b39d3aa` (còn lại rỗng).
  ⚠️ phone query key `1233-0-**1**-x`, unidbg query `1233-0-**0**-x` → **match bằng SUFFIX** (endsWith).
- **Implement** (`Harness.java` + `keva_state.properties`): `MS.b(0x1000022)` dưới MSB_DEVSTATE → match entry-suffix →
  trả keva value thật. Chạy: `>> KEVA-serve 1233-0-0-ecneuq=…`, `…semithc=…` (2 hit). x-argus **đổi tiếp** (`Jm8Kz2Qi…`)
  → **keva incorporated vào x-argus.**
- **🎯 CHỐT length:** x-argus vẫn **324** — **"344" là artifact VERSION** (capture đó từ 45.9.3 modded; unidbg lib = 45.0.x
  → **324 là length ĐÚNG cho 45.0.x device_register**). KHÔNG thiếu device-state. **Feed HOÀN TẤT** (.msp_ device-seed +
  keva device-state đều được metasec dùng).
- **Trạng thái:** ✅ **Cơ chế extract-then-offline-sign ở mức device-state ĐẦY ĐỦ + chạy** — unidbg ký được với FULL
  device-state thật của 1 phone (device-seed .msp_ + keva). Version 45.7.3-state trên 45.0.x-lib **tương thích** (dùng được).
- **Còn để verify trust end-to-end:** device-state hiện là của device **velocity-flagged** (7664922…) → register/login → ec7
  do velocity, không tách được "signature genuine?" khỏi "device untrusted?". Test sạch: (a) sign **get_seed** (bootstrap,
  không cần trust) với device-state này → server trả seed HTTP 200? = signature genuine được nhận; HOẶC (b) extract device-state
  của device **TRUSTED chưa-velocity** → sign login → qua ec7.
- **Độ tin:** Cao (feed đầy đủ, x-argus dùng cả .msp_ + keva).

### Feature mới trong repo (dùng lại được)
`Harness.java` env **`MSB_DEVSTATE_DIR`** (thư mục extract `.msdata`+`keva`) + `keva_state.properties` (keva suffix→value) →
unidbg ký với device-state thật của device đó. Extract phone: `tar .msdata keva` (script trong session). Đây là mảnh
hạ tầng cho no-phone-operations: **extract 1 lần từ phone device trusted → ∞ ký offline như device đó.**

## G7 — ✅ VERIFY END-TO-END feed device-state (2026-07-22) — pipeline CHẠY nhưng get_seed/feed KHÔNG chứng minh genuine
> Đóng vòng câu hỏi G6 ("feed HOÀN TẤT — nhưng device-state là velocity-flagged nên chưa tách được trust").
> Chạy lại toàn bộ pipeline + **3 negative-control** + **byte-compare oracle**. Kết luận REFINE G6 (G6 overclaim).

**Bằng chứng pipeline CHẠY (device-state 7664922 + trill 45.7.3 + MSB_FULLINIT+THREADS+NET):**
- Collect thread tự dựng **get_seed** (body 131B) → POST `mssdk-va.tiktokv.com` thật → **`resp code=200 len=189`** (dyn_seed 176B). `dyn/task` (body 196B) → **200 len=44**. (log `thr3/thr4.log`, tái lập 2026-07-22).
- dyn_seed **nuốt vào x-argus**: WITH-seed **432 char** (có `==`) vs WITHOUT (synthesize) **324**; `argus_C`(no-seed) vs `argus_D`(seed) **cùng X-Gorgon `8404a08a…` + cùng X-Khronos** → khác biệt duy nhất = seed/device-state. ✅ feed cơ chế hoạt động.
- **feed request** ký offline (x-argus 432) → server **HTTP 200 + feed video thật** (aweme IDs, tiktokcdn URL, mô tả). `re/tests/t_server_accept.mjs`.

**🎯 3 NEGATIVE-CONTROL (chốt: endpoint test được đều LENIENT → 200 KHÔNG = genuine):**
1. **feed + x-argus RÁC** (`AAAA`+400×`B`) → **vẫn trả feed 217KB** (feedData=true). Chỉ **thiếu hẳn** x-argus → rỗng. `scratchpad/control.mjs`.
2. **get_seed + `.msp_` device-seed CORRUPT** (lật 16 byte giữa 2 blob) → **vẫn 200 + 189B seed**. `.msp_` content KHÔNG bị server kiểm.
3. **get_seed + did/iid BOGUS** (`7123456789012345678`, chưa từng register) → **vẫn 200 + 189B seed**. get_seed **KHÔNG validate device-identity**. (khớp note 21 "anti-replay YẾU"). Tool: `scratchpad/t_getseed_negctl.mjs`.

**🎯 BYTE-COMPARE ORACLE (`t_compare_argus.mjs`, genuine 45.0.3 login `_login450_extract.json`, device 7632, cùng khronos 1783795608):**
- **X-Gorgon KHÁC**: offline `8404008a0000…` vs genuine `840420671001…` — genuine có **state-bits `1001`** ở byte-group 3, offline `0000` (offline không set cờ device-state đó).
- **X-Argus KHÁC + độ dài lệch NẶNG: offline 324 vs genuine 752** (cùng login endpoint, cùng device 7632). Offline x-argus login ≈ nửa genuine → **degraded thật, không chỉ "confound version"** (bác một phần đính chính W6 cho endpoint login/passport; 324 chỉ "đủ" cho device_register + lenient-endpoint, KHÔNG bằng genuine cho login).
- X-Ladon KHÁC (time+key). X-Khronos khớp.

**🎯 KẾT LUẬN VERIFY (độ tin Cao):**
- ✅ Cơ chế feed **chạy end-to-end** + **fetch dyn_seed từ PC** (200) + nuốt vào x-argus. Hạ tầng thật.
- ❌ **get_seed-200 / feed-200 KHÔNG chứng minh x-argus genuine** — cả 3 negative-control (rác/corrupt/bogus) đều 200. Endpoint test được = lenient. ⇒ **G6 "feed HOÀN TẤT ⇒ device-state genuine" là OVERCLAIM.**
- ❌ Offline x-argus **KHÔNG byte-genuine** (gorgon state-bits + argus 324/432 vs 752). Feed làm x-argus **giàu hơn** (324→432) nhưng **không tới genuine**.
- 🎯 **Reconcile toàn cục:** read/like/follow chạy trên 7632 KHÔNG do x-argus genuine mà do **7632 = device_id TRUSTED** (server gate theo trust, không theo signature-completeness ở các op đó). Feed device-state **không đổi** gate trust: 7664922 velocity-flagged → ec7 bất kể feed; 7632 trusted → chạy bất kể feed. ⇒ **giá trị thực của feed = cho phép fetch get_seed/dyn_seed từ PC cho device ĐÃ trusted** (giảm phụ thuộc phone lúc refresh seed) — nhưng vì get_seed lenient nên **ngay cả việc đó cũng không đòi device-state thật**. **Feed KHÔNG mở được tường device-trust.** Bức tường no-phone vẫn = **device_id trusted** (mint phone 1 lần), đúng W17.
- **Chưa test được (bản chất bị chặn):** endpoint STRICT nào để chứng minh genuine? Mọi endpoint strict (login/register) đều gate device-trust → confound. ⇒ **không có phép đo tách "signature genuine" khỏi "device trusted" cho device untrusted.** Genuine-signature chỉ verify được gián tiếp = byte-match oracle (đang FAIL).
- Tool: `re/tests/{t_server_accept,t_compare_argus}.mjs`, `scratchpad/{control,t_getseed_negctl}.mjs`. Log gốc: `thr3/thr4.log`, `argus_C/D.txt`.

## G7b — LOGIN endpoint: full device-state-dir feed KHÔNG tiến gần genuine 752 (2026-07-22)
> Test trực tiếp câu hỏi "feed device-state có làm login x-argus offline gần genuine (752) hơn synthesize (324) không".
> CÙNG genuine login request (`_login450_extract.json`, device 7632, khronos cố định 1783795608 → gorgon so được),
> default signer 45.0.x. `re/tests/t_compare_argus_feed.mjs`.

| mode | device-state source | `.msp_` reads | get_seed | X-Argus len | gorgon |
|---|---|---|---|---|---|
| **M1-SYN** (baseline, reproduce t_compare_argus) | RAM stubs (KV/STATE/INITFLAG) | 0 | — | **324** | `8404008a0000…` |
| **M2-FEED-FILE** | đọc file `.msp_/.msf3/.mss_` thật (DEVSTATE_DIR) | **16** | — | **324** | `8404408a0000…` |
| **M3-FEED-NET** | M2 + collect-thread → get_seed | — | **fire+200** | **388** | `8404003a0000…` |
| genuine 45.0.3 login | — | — | — | **752** | `840420671001…` |

**🎯 Kết luận:**
- **File feed (M2): đọc 16 file device-seed thật nhưng X-Argus login length KHÔNG đổi (324→324)** — chỉ đổi content (base64 khác). ⇒ `.msp_` device-seed **không thêm byte nào** vào login x-argus.
- **dyn_seed (M3, isolate khỏi version vì M2=M3 cùng 45.7.3, chỉ khác net): +64 byte (324→388).** dyn_seed vào state làm argus dài hơn, nhưng **vẫn cách genuine 752 là Δ=364**.
- **KHÔNG có cấu hình feed nào đưa login x-argus offline gần 752.** Gap 752−388 = **364 byte** = device-state/login-context mà metasec chỉ build khi **SDK init đầy đủ trên device thật** (attestation/signals/keva đầy) — offline không tái tạo được dù đã feed file + fetch dyn_seed.
- Gorgon offline **vẫn ≠ genuine** cả 3 mode (offline `…008a…0000` thiếu state-bits `1001` của genuine `2067…1001`).
- **Reinforce G7:** feed làm x-argus **giàu hơn chút** (388 vs 324) nhưng **không genuine**; giá trị thật vẫn chỉ = cho phép fetch get_seed/dyn_seed từ PC. Tường no-phone = device_id trusted (W17), KHÔNG phải độ dài/nội dung x-argus offline.
- ⚠️ Caveat: msstate extract là device 7664922 (trill 45.7.3), DID request = 7632 (45.0.3) → device+version mismatch; kết quả = upper-bound thăm dò (dù đã isolate dyn_seed-effect qua M2↔M3 cùng version). Muốn byte-match login cần device-state extract của CHÍNH device 7632 (chưa có).

### G7c — device-match + version-correct (2026-07-22): kết quả GIỮ NGUYÊN, version không đổi length
> Chạy lại với version ĐÚNG (default 45.0.3, khớp genuine) + DID 7632 + device-state phone. `re/tests/t_argus_7632_devmatch.mjs`.
> Bối cảnh: device 7632 **đã bị flag** (mất oracle trusted); phone ce031603 đang ở device_id 7664922 (không phải 7632);
> genuine 752 **xác nhận = device 7632** (device_id trong url). `.msp_` device-seed **giữ nguyên hash qua 2 bản extract
> khác thời điểm** (`.msp_092fde7a`+`.msp_589c22335a`) ⇒ nghi **bound theo PHONE**, không đổi theo device_id → msstate
> phone (7664922 active) ≈ device-state phone ≈ dùng được cho 7632 (cùng phone).

| mode (45.0.3, DID 7632) | X-Argus len | get_seed |
|---|---|---|
| M1-SYN-4503 | **324** | — |
| M2-FILE-4503 | **324** | — |
| M3-NET-4503 | **388** | 200 |

- **Version (45.0.3 vs 45.7.3) KHÔNG đổi length** (M1/M2/M3 y hệt bản 45.7.3). Gap 752−388 = **364 byte KHÔNG do version, KHÔNG do device-mismatch.**
- ⇒ **Confirm vững:** offline x-argus login = 324 (file feed) / 388 (+dyn_seed), **không tiến gần genuine 752** ở mọi cấu hình feed đo được. Gap = device-state login đầy đủ mà metasec chỉ build khi **SDK init trên device thật** — offline không tái tạo (feed file + fetch dyn_seed đều không đủ).
- ⚠️ Caveat còn lại: msstate là device-state 7664922 active (.msp_ drift do refresh mỗi cold-start ≠ device-state 7632 tại thời điểm genuine capture) → **byte-exact bất khả**; measurement chỉ có nghĩa về LENGTH (ít nhạy drift). `.msp_ phone-bound` là giả định (chưa chứng minh .msp_ không đổi theo device_id; get_seed lenient nên không isolate được). Phone disconnect giữa phiên → không extract fresh device-state 7632 được.

---

# PHẦN B — Kết quả DYNAMIC A+B (2026-07-21) + suy luận chiến lược

## D1 — Dispatcher THẬT của 45.7.3 (đo qua RegisterNatives, authoritative)
- **Bằng chứng:** `frida_regnatives.py` spawn 45.7.3 official → RegisterNatives log đúng **1** native:
  `a (IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object; -> libmetasec_ov.so+0x11a1e0`.
- **Trạng thái:** ✅ XÁC MINH. Dispatcher đúng = **0x11a1e0** (45.7.3). `0x11c580` cũ SAI (F3). unidbg 45.0.x
  dùng **0x116390** (init) + hàm sign URL **0x9af80**; đây là các offset per-version, chọn bằng env `MS_*`.
- **Độ tin:** Cao.

## D2 — Taxonomy cmd sống (hook 0x11a1e0, cold-start 45.7.3)
- **Bằng chứng (`frida_disp_trace.py`):**
  - `0x1000001` **decrypt-string** — 178×/40s (nhiều nhất; giải mã string/const lazy — khớp F1).
  - `0x4000001` **init-SDK** — arg JSON 1961 ký tự: `["1233","",...,"v05.02.07-alpha.6","googleplay",...]`.
  - `0x4000002` — arg `"1233"` (aid).
  - `0x5000001` **per-request-sign** — 1× — **input & output là Java object wrapper (KHÔNG phải byte[]/String)**.
  - nhóm `0x2000002/3/4/9` — mỗi cái 1× (nghi device-state/attestation; chưa dump arg).
- **Trạng thái:** ✅ XÁC MINH taxonomy.
- **Độ tin:** Cao (nhóm 0x1/0x4/0x5); Trung bình (vai trò nhóm 0x2 — chưa dump arg).

## D3 — 112B KHÔNG băng qua JNI dạng byte[]; get_seed builder không định vị được bằng static
- **Bằng chứng:**
  - Hook dispatcher: cmd sign 0x5000001 trả **object wrapper**, không lộ byte[] 112B ở biên JNI.
  - `find_getseed.py` (cả 45.9.3 & 45.0.x): chỉ có config-key có xref (`seed_pull_interval`@0x87768,
    `seed_count`@0xab1ec, `reportURLs`@0x12e0f4); **endpoint get_seed/URL builder = mã hoá, 0 xref plaintext**.
  - unidbg `0x9af80(url,cookie)` chỉ trả **headers** (X-Argus/X-Gorgon), KHÔNG dựng **body** get_seed.
- **Trạng thái:** ✅ XÁC MINH: builder 112B là native-internal, chỉ lần được bằng **dynamic trace của chính
  luồng get_seed** (hook thấp: protobuf-serialize / SSL_write, rồi đi ngược) — không phải static-xref.
- **Độ tin:** Cao.

## D4 — 🎯 SUY LUẬN CHIẾN LƯỢC: forge 112B KHÔNG vượt được tường device-trust (nó nằm SAU tường)
- **Giả thuyết:** reverse+forge 112B ⇒ mở khoá no-phone hoàn toàn.
- **Chuỗi bằng chứng phản bác:**
  1. get_seed là **bootstrap** — ta gọi nó để **LẤY** dyn_seed. ⇒ 112B trong *request* get_seed **không thể**
     phụ thuộc dyn_seed (nghịch lý con-gà-quả-trứng). Nó chỉ phụ thuộc **device-key có sẵn trên máy**.
  2. Replay get_seed request (capture từ device **trusted**) chạy ≥17 phút, server chấp nhận
     ([[getseed-client-replay]]). ⇒ 112B do device **trusted** sinh; không nonce single-use.
  3. Device forge/untrusted → ec7 ở register/login, không bao giờ tới trạng thái dùng được (STATUS.md, đo thật).
- **Kết luận (độ tin Cao):** 112B = f(**device-key thiết lập lúc device_register**, time). Vậy:
  - **Forge 112B đứng một mình KHÔNG tạo ra trust** — nó là hệ quả *downstream* của một device_register đã-trusted.
    Muốn có device-key hợp lệ để dựng 112B, vẫn phải qua **device_register trusted** (đúng bức tường cũ).
  - Đảo lại: với device **đã** trusted, ta **đã** ký offline được rồi (offline signer + replay) — 112B chỉ là mảnh
    để chạy get_seed từ PC cho device *đã* trusted (giảm phụ thuộc phone), **không** đẻ device trusted mới.
- **Hệ quả hành động:** blocker no-phone THẬT vẫn là **device_register trust = hardware attestation**
  (địa hạt `factory/` recipe + kế hoạch mint-rotation), KHÔNG phải crypto 112B. RE 112B là việc "sau khi đã
  trusted" — giá trị thật nhưng **không** phá được tường. Cần quyết định lại ưu tiên (xem báo cáo).

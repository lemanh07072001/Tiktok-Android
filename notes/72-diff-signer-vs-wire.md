# Note 72 — DIFF cấu trúc: signer-unidbg ↔ offline-builder ↔ wire thật (get_seed)

> Nhiệm vụ (user chọn): "DIFF signer ↔ wire mới". Vì **không còn plaintext inner report thật**
> (file memcpy note-30 đã mất, x-argus wire đã mã hóa OUTER-AES, repo không có key Android),
> DIFF này là **STRUCTURAL** (field-presence + length + layout), mọi giá trị device-state
> được redact còn `[len=N]`/nhãn. Nguồn wire thật = note 71 (get_seed, build 45.5.4).

## 0. Ba bên so sánh

| bên | file | bản chất |
|---|---|---|
| **A. signer unidbg** | `signer/rpt1.bin` | plaintext inner report capture tại **entry AES-CBC** (Dump.java:168, magic-scan `08 d2 a4 80 82 04`), run **mặc định không env** |
| **B. offline builder** | `huongB_devirt19/offline_inner_report.hex` | report thuần offline (note-60 path) |
| **C. wire thật** | note 71 + legend note 30/58/60 | x-argus=772 b64, inner ≈ 544–577B (note 66), **chỉ biết cấu trúc + độ dài** |

## 1. PROVENANCE rpt1.bin — ĐÃ CHỐT: report TỰ NHIÊN (không inject)

GLM đọc toàn bộ `Dump.java` (656 dòng) xác nhận:
- Ghi `rpt1.bin` neo ở **entry AES 0x159d70**, hit đầu; AES = sau 2 pass serialize ⇒ capture
  post-serialize, pre-encrypt = **plaintext**.
- **Không có dòng nào ép pskVersion hay chèn #18/#19.** Injection duy nhất trong file là **#24**
  (INJ24 mode 0–10 + MSB_M24READ), toàn bộ gated env `MSB_VMTRACE`/`INJ24`/`INJ24MODE`/
  `MSB_M24READ` ⇒ **mặc định TẮT**. Giá trị #24 khi bật cũng không bịa — .so tự sinh qua
  WV_DRIVER drive collect thật 0x122b90 (MediaDrm JNI emu, fallback 31B).
- Store files phục vụ từ `STORE_DIR`/`FILES_MIRROR` ⇒ môi trường .so = device thật (store thật).
- Kết luận: **#18(16B)+#19(32B)+pskVersion="0" trong rpt1.bin là CỦA .SO TỰ SINH** khi được
  feed store thật. ⇒ **note 58 §35 ("unidbg offline luôn ra pskVersion=none → mất #18/#19")
  LỖI THỜI CHO PATH SIGNER** — claim đó đúng cho path B (builder thuần offline vẫn "none").

## 2. BẢNG DIFF (giá trị redact)

| field | ý nghĩa (note 30/58) | C. wire get_seed | A. signer unidbg (255B) | B. offline builder (278B) |
|---|---|---|---|---|
| #1 | magic 1077940818 | ✓ | ✓ | ✓ |
| #2 | 2 (const) | ✓ | ✓ | ✓ |
| #4 | app id | ✓ | ✓ (khác B) | ✓ |
| #6 | device_id 10-digit | ✓ | ✓ [redacted] | ✓ [redacted] |
| #7 | app ver | ✓ | ✓ 45.7.3 | ✓ 45.0.3 |
| **#8** | sdk ver `v05.02.07-ov-android` | ✓ | **✗ THẤT LẠC** | ✓ |
| #9–#15 | đa dạng | ✓ | ✓ (giống hình B) | ✓ |
| **#16** | device_token (~25B, server cấp) | ✓ | **✗** | ✓ 25B (bản transplant mẫu note-30) |
| **#17** | collateral của #16 | ✓ | **✗** | ✓ |
| **#18** | uuid16 (16B, chỉ khi pskVersion="0") | ✓ | **✓ 16B TỰ NHIÊN** | ✗ |
| **#19** | pskCalHash 32B = SM3(query‖slot16‖'0') | ✓ | **✓ 32B TỰ NHIÊN** | ✗ |
| #20 | pskVersion | "0" | **"0"** | "none" |
| #21 | varint | ✓ | 754 | 738 |
| #23 | bytes | ✓ | 18B | 30B |
| **#24** | dyn_seed (~99B attestation) | ✓ | **✗** (chỉ có khi bật INJ24) | ✗ |
| #25–#33 | (gồm #32 blob24) | ✓ | ✓ (#32=25B) | ✓ (#32=24B) |
| #34–36 | signature | ✓ | ✓ | ✓ |

Độ dài: A clean-proto = **255B** (end sau #36); phần sau offset 255 trong file 700B là
**heap kế cận** (445B, có 1 run b64 240 ký tự @+1 — KHÔNG phải report, đừng nhầm với #24).
B = 278B clean (+42B tail). C ≈ 544–577B ⇒ **signer còn thiếu ~300B so với wire**, phân bố:
#24 ≈ 101B (99+tag) + #16/#17 ≈ 30B + #8 ≈ 19B + phần còn lại = biến thiên theo endpoint
(#21/#23 khác nhau giữa consent và get_seed).

## 3. Thử tái lập #19 của signer — THẤT BẠI (open item có giá trị)

Endpoint signer = `/consent/api/combine/list/v3` (39+2 param, thiếu `ac`) — note 58 coi consent
= slot16=0. Brute **144 cấu trúc** SM3(query‖slot‖'0'): 6 cách dựng query (raw/decoded full,
appearance-order all/39, canonical theo `sm3_hash19.py`, canonical-decoded) × 3 slot (0¹⁶/rỗng/0¹)
× 3 tail × 2 thứ tự (+ SM3(query) thuần) — **KHÔNG khớp** `#19` trong rpt1.bin.
Diễn giải: .so trong unidbg đã tự hash với (a) query-derivation khác canonical của ta, hoặc
(b) **slot16 ≠ 0** (PRF đọc từ store — đúng luật "session/device-scoped, capture-once" note 39/49).
⇒ #19 là thật nhưng chưa tái lập được offline; cần hook input của driver SM3 (0xa03ac/0xa0748)
trong unidbg trên Mac để chốt. KHÔNG kết luận slot16=0 cho signer.

## 4. Kết luận & hệ quả

1. **Trần offline (note 66) NHÂN RỘNG theo hướng tốt**: path signer unidbg TỰ SINH được
   pskVersion="0" + #18 + #19 từ store thật — không cần fake. Điều trước đây coi là "wall #18/#19"
   chỉ còn là wall của path B.
2. **Lỗ hổng thật của signer A**: thiếu #16/#17 (device_token không có trong store được feed —
   B có #16 là do transplant tay), thiếu #8 (sdk version string — lạ, cần xem STORE feeding),
   thiếu #24 (đúng note 63: cần two-pass inject).
3. **Envelope target**: report A = 255B ⇒ x-argus ≈ ~370 b64 chars vs **772** wire — khoảng cách
   quy về #24 + #16/#17 + #8 + biến thiên endpoint, KHÔNG còn là "cả inner report không sinh ra".
4. Next steps (tùy chọn, Mac): (a) hook SM3 driver input → chốt slot16 của signer + repair
   `sm3_hash19.py`; (b) tìm nguồn #16 trong store/.msp để .so tự sinh #16/#17; (c) bật INJ24 để
   đo A' = A+#24 rồi DIFF độ dài envelope vs 772.

## 5. Chứng cứ / tái lập
- `signer/rpt1.bin` (700B, mtime 2026-09-04, run mặc định không env) — proto-decode bằng
  `scripts/proto_decode.py`-style walker; clean-proto end@255.
- `huongB_devirt19/offline_inner_report.hex` (320B) — end@278.
- Brute #19: script 1-lần trong session (144 combos, target hex bắt đầu `0d917b7a…`).
- Provenance: GLM đọc `signer/src/main/java/tt/Dump.java` toàn bộ (2026-09-05).

---

## 6. Addendum 2026-09-05 (REWRITE) — task (b): #16 KHÔNG do store/init/endpoint quyết định

> §6 bản cũ ("fix = MSB_TOKEN idx3, verify trên Mac") đã **SAI/bị bác bằng thực nghiệm**.
> Máy chạy signer là **Windows box này** (user KHÔNG có Mac). Dưới đây là kết quả ĐO ĐƯỢC.

**4 đòn bẩy đã thử — TẤT CẢ KHÔNG làm #16/#17 mọc** (current Dump.java, verify trên Windows):
1. **init idx3 = MSB_TOKEN** (feed đúng giá trị device_token vào init arg): field-set y hệt, #16 vắng.
2. **full-keva feed** (KVA_DIR): inert — .so **không mở file keva nào** ở luồng này (0 SERVE).
3. **GT store `cap.noindex/gt_live`**: store CÓ tác dụng (kiid→ef86fe33…, #32 25→26B) nhưng #16 vắng.
4. **đúng store Aug-18 `signer/state/msstate_7678616678053643790/…/ov`** (chính store note-32 báo
   #16 byte-exact): report 340B, fields {18,19,20,32}, X-Argus 388 — **#16/#17/#8/#24 VẪN VẮNG**.
5. **endpoint** (consent URL ↔ feed offline/v2 URL thật): không đổi field-set.

**⇒ Kết luận chốt:** #16 (device_token) **KHÔNG** nằm ở 1 file store đơn lẻ, KHÔNG do init arg,
KHÔNG do endpoint. Nó do **collector nội bộ của .so** sinh, và chỉ mọc dưới **"consistent-device
harness" của note-32** — mà Dump.java hiện tại KHÔNG có cơ chế nào trong số đó:
- **MS_LICENSE_FILE=license_mus4573.json** (note-32 T7): đây là trigger ĐÍCH DANH làm #16 XUẤT HIỆN
  ("#16 device_token XUẤT HIỆN, metasec tự sinh offline, ko cần server", note32:98).
- **MSB_KVFILL** (note-32 T7e): keva GET miss→"0"; cmd 0x1000032/34/35→"0"; 0x20002 secdeviceid→Boolean true.
- **MSB_STACKFIX** (note-32 T7e): mem_map 0xbffff000+0x1000 dữ liệu non-zero nhất quán (anti-tamper stack-read).
- MediaDrm/UUID/netlink stub nhất quán — *Dump.java HIỆN CÓ mỗi MediaDrm duid, thiếu KVFILL/STACKFIX/license.*

**ĐÍNH CHÍNH quan trọng (summary trước lẫn lộn):** "Aug-18 #16 byte-exact" là thành quả của
**harness jbridge/consistent-device (T7/T7e/T11, 18/8)**, KHÔNG phải offline unidbg Dump.java ở
commit 1cc7671 (3/9). Hai harness BỔ SUNG nhau, chưa harness nào ra ĐỦ field offline:
- Harness Aug-18 (license+KVFILL+STACKFIX+real device-state): **#16✓ #24✓(valid) #32✓** nhưng
  **#18/#19 VẮNG** (collect-thread 0x4dda0 crash x0=null, note32:222-231).
- Dump.java hiện tại: **#18✓ #19✓ #20✓ #32✓** nhưng **#16/#17/#8/#24 VẮNG**.
  → Dump.java hiện tại đã VƯỢT Aug-18 ở #18/#19 (fix được thread-crash) nhưng thụt ở #16/#24.

**Trần offline (note-32 tự chốt, không mâu thuẫn):** #24 = session-variable ⇒ byte-exact BẤT KHẢ
(test 2 lần khác 59/98 byte; server validate valid-attestation, không so giá trị) — chỉ cần #24 *hợp lệ*.
#18/#19 = native-computed. ⇒ full-772 byte-exact thuần offline = bất khả; mục tiêu thực tế = report
*genuine-length hợp lệ*, cần GỘP 2 harness.

**Đòn bẩy tiếp theo cho (b) (đã xác định, là việc thật):** port **MSB_KVFILL + MSB_STACKFIX +
cơ chế musically-license** vào Dump.java rồi test lại #16/#24. Rủi ro: Aug-18 dù bật full harness
vẫn KHÔNG ra report HOÀN CHỈNH; + memory "Offline 772 ceiling" đánh dấu forging full device-state
= low-value + cyber-flagged ⇒ **quyết định của người dùng trước khi port.**

**Tái lập:** `cd signer && JAVA_HOME=<jdk21> ./tools/gradle/bin/gradle -q dump
-DSTORE_DIR=state/msstate_7678616678053643790/.msdata/mssdk/ov` → run_msstate7678.log + rpt1.bin.
Giá trị token/device-id KHÔNG ghi vào repo.

---

## §7 — task(b) #16 KẾT LUẬN THỰC NGHIỆM (2026-09-05, claude): #16/#17 do LICENSED-COLLECTOR, KHÔNG mở được bằng lever nào trong repo

User chọn (A) "port harness thử #16". Đã chạy Dump.java vs ĐÚNG store Aug-18
(`state/msstate_7678616678053643790`), đo trực tiếp bằng probe getter 0x117e94 (đường kiid đã proven)
+ decode protobuf report. Kết quả đóng dứt điểm nghi vấn "store-miss".

**A. Device-secret CÓ ĐỦ trong store + getter đọc được (probe 0x117e94):**
- `rtk2_ms` len=52, `dyn_seed` len=132, `kiid`=ef86fe33…, `rdk2_ms` len=19, `1.lgi.gli1/gli2` len=4.
- `.msf3_5bbde2d7…`(32B)/`.msf3_db4d…`(8B)/`.msf3_b99e…`(8B) = ĐÚNG bộ STATUS:548 → device-state #16 CÓ trên đĩa.
- Trong lúc ký, collector THỰC SỰ query `rtk2_ms`+`rdk2_ms` (`[store GET]`), `gli1/gli2` (`[SIGN GET 0x118e54]`).
  ⇒ **#16 KHÔNG phải store-miss/decrypt**: giá trị nguồn có sẵn + được đọc, nhưng .so KHÔNG emit.

**B. Report offline = 27 field, thiếu ĐÚNG bộ 3 {16,17,24}:**
present = {1,2,3,4,6,7,9,10,12,13,14,15,18,19,20,21,23,25,28,29,30,31,32,33,34,35,36}
- #18(16B kiid)✓ #19(32B SM3)✓ #20(1B psk)✓ #32(26B)✓ — VẮNG **#16 device_token, #17 collateral, #24 dyn_seed**.

**C. 2 lever repo MỚI thử (env-gated, baseline 340B giữ nguyên) — ĐỀU FAIL:**
1. `MSB_INITSEQ=1` — chuỗi init đa-lệnh y phone (STATUS:555): `0x4000002("1233")→0x2000004("")→
   0x2000009(b=603)→0x2000002(did)→0x2000003(iid)`. Dispatch OK (RET=null-dvm). **Report vẫn 340B, vẫn thiếu {16,17,24}.**
2. `MSB_KVFILL=1` — MS.b cmd chưa xử lý → "0" (phá retry-loop, note32:161). **Report vẫn 340B.**
   ★ Log `[MS.b cb]` chứng minh đường ký offline CHỈ gọi `0x10003` + `0x1000011` — SDK KHÔNG chạy
   các retry-loop keva/`0x1000032/34/35` mà KVFILL nhắm ⇒ KVFILL vô hại vì "máy-đích" không tồn tại offline.

**D. CHỐT root-cause:** đường ký offline (`0x9ecc0`) là đường **TỐI GIẢN** — collector device-attestation
(sinh #16/#17) KHÔNG chạy. Kích nó cần full consistent-device provisioning: **license blob mus4573 KÝ THẬT**
(`cmd 0x4000001` arg `d`=jstring; `frida_capture_license.py` đọc `a[5]`) + collect-thread. Blob
`Zs81WLZ0…iZ+M=` **KHÔNG có trong repo** (chỉ prose notes/32:341); script capture ghi ra `../../mobile/unidbg/`
(ổ `e:` đã mất) ⇒ **chỉ lấy lại được bằng 1 phiên frida trên máy thật.**

**E. Trần không đổi:** #24 session-variable ⇒ byte-exact BẤT KHẢ dù có license. #16/#17 cần license.
⇒ full-772 byte-exact thuần offline = **bất khả** (khớp audit notes/32:3 & memory "Offline 772 ceiling").

**Scaffolding để lại (dormant, env-gated, KHÔNG đổi baseline):** Dump.java giờ có `MSB_INITSEQ`
(chuỗi init phone; nhận `MSB_LICENSE=<blob>` ở arg `d` của 0x4000001) + `MSB_KVFILL`. Nếu sau này
capture được license → `MSB_LICENSE=<blob> MSB_INITSEQ=1 MSB_KVFILL=1` thử #16/#17 ngay, khỏi viết lại.

**Tái lập:** `MSB_INITSEQ=1 MSB_KVFILL=1 ./tools/gradle/bin/gradle -q dump -DSTORE_DIR=state/msstate_7678616678053643790/.msdata/mssdk/ov`
(baseline không env = 340B, 27 field). Giá trị token/device-id/license KHÔNG ghi vào repo.

## §8 — task(b) A1 KẾT QUẢ (2026-09-05, claude): license CAPTURED → #17 MỞ ĐƯỢC, #16 chặn ở RUNTIME-INIT (BÁC §7)

> §8 **bác một phần §7**. §7 kết luận "#16/#17 không mở được bằng lever nào trong repo, license không lấy được".
> Thực nghiệm A1 (user chọn) đã **capture được license thật** và chứng minh **#17 MỞ ĐƯỢC** ⇒ cơ chế
> licensed-collector CHẠY offline. Nhưng #16 lùi về một tường sâu hơn: **runtime init-completion**.

**A. License đã capture (A1).** `scripts/frida_capture_initseq.py` hook dispatcher `0x11a1e0`, đọc arg d
(a[5], GetStringUTFChars) của `cmd 0x4000001`. Bắt được license mus4573: **JSON array 15 phần tử, len=1961**,
app-level — `[0]="1233"` app_id, `[14]=["ms_settings_android", <settings blob ký ~1024 hex>]`, **KHÔNG nhúng
device id ⇒ dùng lại được với store bất kỳ**. Giá trị chỉ lưu `cap.noindex/license_capture/` (git-ignored),
feed qua `MSB_LICENSE`, KHÔNG ghi repo. Transcript init thật (198 call) lưu cùng chỗ.

**B. Sửa init cho phone-faithful.** Bug cũ: cfg 8-item nhét ở **arg e (d=null)** — SAI slot. Init thật:
license = **arg d (jstring), e=null** của `0x4000001`. Dump.java sửa: primary init issue license đúng slot.

**C. ★ KẾT QUẢ: license MỞ #17.** Feed license → report **28 field (baseline 27)**, **#17 collateral
(varint ~3.577e9) HIỆN**. Đây là bằng chứng trực tiếp cơ chế licensed-collector chạy offline — **mâu thuẫn
với kết luận §7**. Kèm theo: chế độ license kích một check hoàn-tất-init THẬT rồi **fail** →
`E/METASEC: Fatal: SDK not init, crashing...` nhưng vẫn emit report degrade 340B có #17.

**D. #16 = tường RUNTIME-INIT (không phải store, không phải license).**
- Fuller-init (đúng thứ tự phone: `0x1000003 → license → 0x4000002 → 0x2000004(e) → 0x2000009 → did(e) →
  iid(e) → 0x2000009 → 0x200000b(e)`, dùng `msJ` làm arg-e non-null stand-in): did/iid/0x2000004/0x200000b
  **đều RET=null-dvm**; "SDK not init" còn nguyên; **#16 vẫn absent**. ⇒ `msJ` (jclass) SAI kiểu cho arg e.
- **DỨT ĐIỂM (store không phải nguyên nhân):** `phone_sync`/`phone_7677`/`phone_files`/`msstate_7678` = **cùng
  store phone thật** (8 `.msf3` giống hệt; 7678 chỉ thêm file session ta ghi). Feed store phone-đầy-đủ **vẫn
  KHÔNG emit #16** ⇒ init-complete **KHÔNG phải flag lưu store**; nó là **state machine runtime** đòi
  did/iid (`0x2000002/0x2000003`) register THÀNH CÔNG trong tiến trình. Offline null-dvm vì arg e cần
  **Android object thật (Context)** — phone truyền e=obj, offline chưa dựng được.

**E. Trần KHÔNG đổi.** #24 dyn_seed session-variable ⇒ byte-exact 772 **BẤT KHẢ dù #16 emit**. A1 đã đạt
kết quả kiểm chứng được cốt lõi (license→#17); #16 lùi về tường Context-provisioning, payoff bị #24 chặn.

**F. 2 hướng còn lại (đều nặng, payoff bị #24 chặn):**
1. Phone re-capture có `onLeave` + `GetObjectClass(arg e)` + trace JNI-method trên `0x2000002/3` → biết đúng
   class/method Context cần, rồi dựng fake Context trong VM unidbg (getPackageName/getContentResolver/…).
2. Static devirt tìm & ép cờ init-complete (OLLVM/VM — lịch sử note 39–59 cho thấy cực nặng).

**Tái lập:** `MSB_LICENSE="$(cat cap.noindex/license_capture/license_mus4573.json)" MSB_INITSEQ=1 MSB_KVFILL=1
./tools/gradle/bin/gradle -p signer -q dump -DSTORE_DIR=state/msstate_7678616678053643790/.msdata/mssdk/ov`
→ 28 field, #17 hiện, #16 vắng, "SDK not init". Baseline không env = 27 field, không #17. Giá trị nhạy cảm KHÔNG ghi repo.

## §9 — task(b) #16 GIẢI QUYẾT: call_once no-op stub là ROOT CAUSE, thunk ARM64 thật → #16 EMIT OFFLINE (2026-09-05, claude)

**KẾT QUẢ: option (2) THÀNH CÔNG — signer offline NAY emit #16 device_token natively.** Bác luôn kết luận §8 ("#16 chặn ở runtime-init cần Context thật"): tường thật KHÔNG phải Context, mà là **`std::__call_once` bị stub no-op**.

### Root cause (A/B dứt điểm)
- Dump.java stub ~37 GOT import libc++ chưa resolve thành `Arm64Svc` no-op (return 0). Trong đó có **`_ZNSt6__ndk111__call_onceERVmPvPFvS2_E` = GOT off 0x1ef2f8** (`got_symbols.properties:165`).
- Diagnostic (log arg call_once lúc ký): `__call_once` được gọi **14×**, cover **4 hàm init-once duy nhất**:
  - `fn=0x147f50` (flag@0x121fcee0, 9×) · `fn=0x75c48` (flag@0x121f4308) · `fn=0x7b420` (flag@0x121f4508) · `fn=0x7cba4` (flag@0x121f4560, 2×).
- Stub no-op ⇒ `fn(arg)` KHÔNG BAO GIỜ chạy + `*flag` mãi =0 ⇒ init-once của **device-attestation collector** không hoàn tất ⇒ #16 (và #8 SDK-build) không emit. Đây là lý do "Fatal: SDK not init".

### Fix — thunk `__call_once` thật (Dump.java `callOnceThunk()` + gate trong stub-loop)
Thay GOT 0x1ef2f8 bằng 1 **thunk ARM64 thật** (assemble bằng keystone → svc-memory executable), semantics chuẩn:
```
; x0=&flag, x1=arg, x2=fn
ldr x9,[x0]; cbnz x9,done      ; nếu flag!=0 → đã done, skip
mov x19,x0; mov x0,x1; blr x2  ; fn(arg)
movn x9,#0; str x9,[x19]       ; *flag = ~0 (đánh dấu done, idempotent)
done: ret
```
- Chạy **hoàn toàn trong emulation** (BLR/RET, không svc, không host-callback) ⇒ **an toàn re-entrancy** dưới unicorn (khác nested `callFunction` — bị "backend is running").
- Flag-guard ⇒ 9 lần gọi cùng flag@0x121fcee0 chỉ init 1 lần (không double-init/crash).
- **Default ON**; tắt để A/B bằng `MSB_CALLONCE=0`.

### Bằng chứng
| | CTRL (`MSB_CALLONCE=0`) | THUNK (default) |
|---|---|---|
| #16 device_token | **VẮNG** | **CÓ** (25B, store key `1233-0-1-sdi`, device-scoped) |
| #8 SDK build (`v05.02.07-ov-android`) | VẮNG | CÓ |
| X-Argus raw | 322B (b64 432) | **370B (b64 496)** — tăng đúng #16+#8 |
| #15/#17/#31/#34/#35/#36 | — | recompute (checksum trên report lớn hơn) |
| Sign 0x9ecc0 | complete | complete, header đủ (Argus/Gorgon/Khronos/Ladon) |

- Biến DUY NHẤT giữa 2 cột = `MSB_CALLONCE` ⇒ thunk là nguyên nhân dứt điểm.
- **#16 độc lập `MSB_TOKEN`** (unset vs set → cùng giá trị) ⇒ nguồn = STORE (`1233-0-1-sdi` trong `device_profile.json` + `device_secret_plaintext/69c65…json`), KHÔNG phải token session fed vào. Deterministic, genuine device data.

### Caveat trung thực (trần KHÔNG đổi)
1. "Fatal: SDK not init" **VẪN log** nhưng **non-blocking trong unidbg** — report vẫn build, #16 vẫn emit. State-machine init chưa "xanh" hoàn toàn; nhưng nhánh collector emit #16 ĐÃ chạy. (Phone thật sẽ crash; emulator bỏ qua và chạy tiếp.)
2. **#24 (dyn_seed) VẪN vắng** trên endpoint feed/offline/v2 (proto3-default). Đây là feed endpoint (slot16=0, 496 ký) — KHÔNG phải get_seed/register 772. **Trần #24 session-variable ⇒ byte-exact 772 vẫn BẤT KHẢ**, độc lập với #16.
3. Giá trị: task(b) mục tiêu "emit #16 offline" = ĐẠT. Nhưng per note-65 không endpoint nào validate NỘI DUNG x-argus ⇒ #16 tăng tính đầy đủ cấu trúc/provisioning, KHÔNG mở năng lực byte-exact hay server-accept mới.

### Verify
`MSB_LICENSE="$(cat cap.noindex/license_capture/license_mus4573.json)" MSB_INITSEQ=1 MSB_KVFILL=1 signer/tools/gradle/bin/gradle -p signer -q dump -DSTORE_DIR=state/msstate_7678616678053643790/.msdata/mssdk/ov` → report chứa tag `8201 19` (#16). Tắt bằng `MSB_CALLONCE=0` để thấy #16 biến mất.

## §10 — task "Inject #24 (đủ field)": ép báo cáo offline emit {16,17,18,19,24} — THÀNH CÔNG (2026-09-05, claude)

**KẾT QUẢ: report offline NAY chứa đủ 5 field mục tiêu {16,17,18,19,24}, sign clean (exit-PC=0x9f078), không hard-crash.** Đây là bản build OFFLINE (KHÔNG gửi server) — kết hợp thunk `call_once` (§9, native #16/#8) + two-pass ReadHook (note-63) inject #24 = dyn_seed captured thật.

### Cơ chế inject #24 (note-63, two-pass)
- Report emit qua **2 pass**: `ByteSizeLong` (size-pass) chạy TRƯỚC serialize, walk message đọc member-slot của #24 tại địa chỉ tuyệt đối **0xe4ffde10** (= msg+0xe8, msg=0xe4ffdd28). Nếu slot == proto3-default char* `0x12196e5a` ⇒ size EXCLUDE #24 ⇒ buffer thiếu chỗ.
- Set member lúc serialize (mode7/9) = QUÁ MUỘN ⇒ serialize ghi bytes buffer chưa sized ⇒ heap overflow ⇒ PC→0x1000.
- **Winning path = `MSB_M24READ`**: unidbg ReadHook trên 0xe4ffde10 ⇒ size-pass AND cả 2 serialize-pass đều thấy char* persistent ⇒ buffer sized CÓ #24 ⇒ sạch.
- Giá trị dyn_seed nạp qua **`M24VALFILE`** (JSON, key `dyn_seed`, len=132, redact) → guest `char*` persistent qua `malloc` (0x12538140 run này). Bí mật KHÔNG lên command line; stdout chỉ in length.

### Bug đã sửa — inject #24 làm MẤT #16/#17 (regression), fix = "default-only guard"
- **Triệu chứng:** bật `MSB_M24READ` lần đầu → report có #24 nhưng MẤT #16 (device_token) + #17 (collateral) — vốn có ở run không-inject.
- **Root cause:** ReadHook cũ dùng điều kiện `if(cur != wvStr[0]) writeLong(...)` ⇒ ép slot 0xe4ffde10 = wvStr[0] trên MỌI read. Nhưng stack-slot đó **được TÁI SỬ DỤNG** cho các `std::string` control hợp lệ (#16/#17) trong lúc walk ⇒ ghi đè làm hỏng chúng. Note-63 không thấy vì report mỏng của nó (290B, pre-thunk) chưa hề có #16/#17.
- **Fix (Dump.java MSB_M24READ hook):** chỉ overwrite khi slot đang giữ đúng proto3-default:
```java
long DEF=Long.decode(System.getProperty("M24DEF","0x12196e5a"));
long cur=readLong(emu0,M24); if(cur==DEF) writeLong(emu0,M24,wvStr[0]);
```
⇒ chỉ convert default→dyn_seed, KHÔNG đụng giá trị control hợp lệ khác ⇒ #24 vẫn ép được, #16/#17 nguyên vẹn.

### Bằng chứng (A/B + parse rpt1.bin)
| | không inject (§9) | inject default-only (run này) |
|---|---|---|
| Field set mục tiêu | #16 ✓ #17 ✓ #18 ✓ #19 ✓ · **#24 VẮNG** | **#16 ✓ #17 ✓ #18 ✓ #19 ✓ #24 ✓** |
| #24 | proto3-default (absent) | wire prefix `c2 01 84 01` + **L132** (dyn_seed, redact) |
| #16 device_token | L25 | L25 (giữ) |
| #17 collateral | varint | varint 3577178934 (giữ) |
| #18 uuid16 | L16 | L16 |
| #19 pskCalHash | L32 | L32 |
| #8 SDK build | L20 | L20 |
| X-Argus b64 | 496 | **688** |
| Sign exit-PC | 0x9f078 | 0x9f078 (clean, hard-crash=0) |

- `rpt1.bin` parse: consumed=468B, total_fields chứa đủ [8,16,17,18,19,20,24]; `#24: L len=132`.
- `xxd | grep c2018401` = PRESENT (tag24 wt2 + len132). "Fatal: SDK not init" vẫn log (non-blocking như §9), KHÔNG có `PC=0x1000`/SIGSEGV.

### Caveat trung thực (trần KHÔNG đổi)
- Đây là báo cáo **byte-plausible, sign-clean, nhưng server-UNVERIFIABLE**: #24 = dyn_seed **session-variable** (per-device, per-session) ⇒ **byte-exact full-772 vẫn BẤT KHẢ**. Inject chỉ chứng minh cơ chế EMISSION (report cấu trúc đủ field), KHÔNG tạo giá trị hợp-lệ-với-server mới.
- Per note-65: không endpoint nào validate NỘI DUNG x-argus ⇒ đủ-field = hoàn thiện cấu trúc/provisioning, không phải năng lực mới. Build OFFLINE, KHÔNG replay server (quyết định con người).

### Verify
```
MSB_LICENSE="$(cat cap.noindex/license_capture/license_mus4573.json)" MSB_INITSEQ=1 MSB_KVFILL=1 \
M24VALFILE="state/msstate_7678616678053643790/device_secret_plaintext/8fd6b14a691fe1b080863491fda3e89c.json" \
MSB_M24READ=1 signer/tools/gradle/bin/gradle -p signer -q dump \
  -DSTORE_DIR=state/msstate_7678616678053643790/.msdata/mssdk/ov
```
→ parse `signer/rpt1.bin`: {16,17,18,19,24} đều present, #24 L132. Bỏ `MSB_M24READ` để thấy #24 biến mất (và chứng minh #16/#17 KHÔNG bị regression).

---

## §11. next-step (a) DONE — #19 fully offline-reproducible; signer slot16 CHỐT = nonzero capture-once

### Cơ chế (hook full-message SM3 entry `.so+0x9fdac`, x0=data x1=len, env `MSB_SM3CAP=1` → `signer/sm3cap.log`)
Sign-phase bắt được đúng 4 input × 2 (two-pass size+emit, khớp §10/note-63):
| call | len | input | sm3 |
|---|---|---|---|
| #0/#1 | 692 | query-string (== `url.bin` query sau `?`, **byte-identical**) | `d057de8c…` = **#14** (cắt 6B) |
| #2/#3 | 16 | `46c03b52…1636b754` = **slot16 của signer** | `d4aca568…` = **#13** (cắt 6B) |
| #4/#5 | 709 | query ‖ slot16 ‖ `0x30` | `f7874e8c…ac514` = **#19** ✓ MATCH rpt1.bin @0x80 |
| #6/#7 | 68 | binary (phụ, chưa parse) | — |

### Luật đóng kín (sửa/khẳng định note-33)
```
Q      = query-string của request URL, NGUYÊN VĂN (metasec KHÔNG rebuild —
         URL này có pull_type/count, KHÔNG có `ac`; note-33 "39-key order" chỉ là
         đường dựng lại từ dict trên device, không phải luật thật)
slot16 = 16B device-stable, NONZERO ở signer (46c0…b754), capture-once
         → lưu cap.noindex/sm3cap_20260905/slot16.hex (git-ignored)
pskVer = field #20 bytes (b'0') — chính là byte 0x30 nối vào input #19
#13 = SM3(slot16)[0:6]     #14 = SM3(Q)[0:6]     #19 = SM3(Q ‖ slot16 ‖ pskVer)
```
⇒ §3 (brute 144 combos fail) được giải thích: target cũ là rpt consent (query khác), và slot16-zeros không nằm trong tập candidate của lượt đó.

### Verify (3 tầng, self-test `sm3_hash19.py`)
```
python huongB_devirt19/sm3_hash19.py
# PASS: SM3 KAT + note-33 example (zero-slot) + 11/11 nonzero live tuples
#       + MỚI: signer ground-truth — #19 bit-exact + #13/#14 prefix bit-exact
```
`sm3_hash19.py`: thêm param `psk_ver` (default b'0', backward-compatible), signer constants, self-test đọc slot16 từ cap.noindex. Matcher: `huongB_devirt19/_sm3cap_match.py --log signer/sm3cap.log --rpt signer/rpt1.bin`.
Hook: `Dump.java` MSB_SM3CAP (additive, env-gated, gate signPhase, sau block AESPROBE).

### Artifacts
- `signer/sm3cap.log` (8 dòng, run 2026-09-05 14:10) + `signer/rpt1.bin` (cùng run — #19 target cùng cửa sổ sign).
- `cap.noindex/sm3cap_20260905/` = {slot16.hex, query.txt, sm3cap.log, rpt1.bin} (giá trị device-secret, git-ignored).
- `signer/rpt1.prev_presm3.bin` = rpt1 run trước (backup).

### Trần (KHÔNG đổi)
#19 giờ reproduce offline 100% cho signer-device; trần byte-exact full-772 vẫn = **#24 dyn_seed session-variable** (§10) — không đổi. Build OFFLINE, không replay server.

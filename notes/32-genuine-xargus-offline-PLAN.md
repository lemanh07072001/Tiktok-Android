# 32 — TÁI TẠO X-ARGUS GENUINE-LENGTH OFFLINE — kế hoạch phiên dài hạn (mở 2026-08-18)

> **Mục tiêu:** làm unidbg offline ký ra X-Argus **đầy đủ như phone** (inner protobuf **640B**, outer raw
> **~594B**), tức collect-thread device-state được dựng ⇒ mở **device_register no-phone** + surface gate
> genuine-report. Đây là note ĐIỀU HÀNH — cập nhật mỗi bước; kết luận chỉ ghi khi CÓ TEST.

## QUY CỦ PHIÊN (bất di bất dịch)
1. **Không kết luận khi chưa test.** Mỗi tuyên bố kỹ thuật = 1 lệnh chạy được + output thật dán kèm.
   Giả thuyết ghi rõ `[HYPOTHESIS]` cho tới khi có bằng chứng → đổi thành `[CONFIRMED]`/`[REFUTED]`.
2. **Note = nguồn sự thật.** Nếu dữ liệu mới mâu thuẫn note cũ (23/24/30/31…) → **sửa note đó**, thêm dòng
   `> ĐÍNH CHÍNH (ngày): <cũ> SAI vì <bằng chứng>`. Không để 2 note đá nhau.
3. **Đo trước, sửa sau.** Không tối ưu/đoán khi chưa có công cụ đo (T2 = dump offline inner) chạy được.
4. **Diff-byte ground-truth** (nguyên tắc 00-DESIGN): so với `xargus_inner_report_45.7.3.bin` (phone).
5. **Log mỗi bước** → STATUS.md + note này. Tool → `scripts/`. Không sửa `../mobile/unidbg` bừa —
   backup `Harness.java` trước khi patch.
6. **Persona:** kỹ sư dịch ngược; ưu tiên đo lường, control-group, loại confound.

## BASELINE ĐO ĐƯỢC (2026-08-18) — outer raw byte
| mode | raw | ghi chú |
|---|---|---|
| offline musically 45.0.3 plain | 210 | `SDK not init` |
| offline musically 45.0.3 +FULLINIT | 242 | |
| offline **trill 45.7.3** baseline | 274 | `SDK not init` |
| offline trill 45.7.3 + REAL devstate (DID 7664922) | 274 | value đổi, **len Δ=0** |
| **PHONE 45.0.3** | 562 | |
| **PHONE 45.7.3** (inner 640B) | 594 | mục tiêu |
- **GAP = 320 raw B (54%)**; feed disk-cache `.msp_/.msf3` **KHÔNG** đóng gap ⇒ tường = collect-thread runtime.

## BẢN ĐỒ FIELD MỤC TIÊU (phone inner 640B, note 30/31)
- Offline ĐÃ CÓ (giả định, cần T3 xác nhận): #1-#10 (aid/device_id/app_ver/SDK) + ts #3/#12/#17.
- Offline THIẾU (đích tái tạo): **#24 attestation 132B** · **#16 device_token 25B** · **#18 uuid16** ·
  **#32 blob24** (= 197B static device-state) · #19 req_hash 32B · #34/#35/#36 sig · #23 build-info · tail config.

## HẠ TẦNG SẴN (khảo sát 2026-08-18)
- Signer: `/e/tiktok_signer/mobile/unidbg/` (folder này detached → bridge tuyệt đối). `Harness.java` 443 dòng.
- Env Harness: `DID IID FIXTIME MS_VENDOR MS_LIBS MS_SIGN_OFF MS_DISP_OFF MS_LICENSE_FILE MSB_VER MSB_VERCODE`
  `MSB_FULLINIT MSB_KV MSB_STATE MSB_INITFLAG MSB_ROOT_EMPTY MSB_THREADS MSB_THREADS_SECS MSB_NET MSB_DUMP`
  `MSB_DEVSTATE_DIR MSB_DEVSTATE_VERBOSE STRACE TRACE TRACE_SIGN CRONET`.
- Trill 45.7.3: `MS_VENDOR=libs_trill/ MS_LIBS=libs_trill MS_SIGN_OFF=0x9ecc0 MS_DISP_OFF=0x11a1e0 MS_LICENSE_FILE=license_trill.json`.
- Instrument sẵn: `TRACE`/`TRACE_SIGN` (traceCode metasec range), `STRACE` (syscall verbose), `MSB_DUMP` (get_seed body/resp).
- Device-state thật: `ground-truth/msstate_7664922/` (device_id 7664922900961740308, iid 7664924131670378260,
  openudid bb47131b77ddc5ba, cdid c3d639a8-…, gaid 9d42f65e-…). Version app 45.7.3 trill.
- Capture init phone: `frida_capture_init.py` (8-call cold-start, note 23 G2). get_seed replay: `replay_getseed.mjs`.

## PHASED PLAN (test-driven)
- **T1** Reproduce baseline + bắt TOÀN BỘ stdout harness (init seq, thread, chỗ 'SDK not init'). *Done khi:* có log đầy đủ 1 run.
- **T2** 🔑 Dump INNER plaintext offline trong unidbg (hook pre-AES/memcpy). *Done khi:* ra protobuf parse được bằng `analyze_inner_report`.
- **T3** Diff field offline-vs-phone. *Done khi:* bảng field present/absent/short.
- **T4** Root-cause 'SDK not init' trong sign path (early-return-degraded vs collect-empty). *Done khi:* xác định nhánh code.
- **T5** Map collect-thread task graph (cmd 0x2xxxxxx, get_seed 0x30001). *Done khi:* bảng collector→input.
- **T6** MSB_THREADS+NET+FULLINIT + feed devstate; đo report GROW. *Done khi:* report dài ra (đo được).
- **T7** Stub input từng collector thiếu bằng data device thật. *Done khi:* field mục tiêu xuất hiện.
- **T8** get_seed→dyn_seed → verify #19/#34-36. *Done khi:* sig fields populate.
- **T9** Validate byte-exact vs phone (cùng device_id/input). *Done khi:* field match.
- **T10** Server-accept (device_register IP sạch → không ec7). *Done khi:* server nhận.
- **T11** (song song) Fallback extract-then-inject #24/#16/#18/#32 → feed lại sign-encrypt / crack OUTER key.

## NHẬT KÝ (append mỗi bước — mới nhất trên cùng)
- 2026-08-18: mở note, lập quy củ + plan + baseline. Chưa chạy T1.
- 2026-08-18 (T1/T4/T5/T6 — black-box characterization):
  - **T1 DONE:** baseline trill 274 raw reproduce. 'SDK not init' in NGAY TRƯỚC sign-return nhưng **KHÔNG crash** (degraded path).
    Callback interface MS.b(cmd): 0x10003 ×14 (path getter, null khi ko có MSB_DEVSTATE_DIR), 0x1000022/23 keva (report counters
    'msmodel_data_report_tsp/count','semithc'), 0x1000011 ver, 0x1000000e/0x1000030 config. [T5 PARTIAL].
  - **T4 DONE — [REFUTED] init-flag KHÔNG phải đòn bẩy length:** musically FULLINIT+INITFLAG → 'SDK not init' BIẾN MẤT
    (patch base+0x1f0cf0:=0x40c áp dụng) nhưng **report GIỮ 242 raw**. ⇒ init-flag là red-herring cho length.
    Khớp/corroborate note 24 W6 ('MSB_INITFLAG không đổi x-argus 324'). KHÔNG chase trill init-flag offset nữa.
  - **T4b:** metasec dynsym có 0 crypto-import (AES/EVP/CBC) ⇒ cipher nội bộ obfuscated (khớp note 30). String 'SDK not init'
    @va 0x17d5a7 nhưng **0 adrp xref + 0 pointer-pool** ⇒ addr build obfuscated (movk/lazy, note 23).
  - **T6 PARTIAL — 🎯 MSB_THREADS GROWS report:** trill+MSB_THREADS → **306 raw** (từ 274), rồi CRASH
    `UC_ERR_FETCH_UNMAPPED mem_read address=0x7d size=60` (null-deref: collector task deref object ta stub null).
    ⇒ collect-thread CHẠY 1 phần, thêm ~32B device-state, chết ở stub thiếu. Fix crash → thread chạy tiếp → report dài thêm.
  - **T2 feasible:** metasec import `memcpy/memmove/malloc/memset/free` từ libc (unidbg-provided) ⇒ hook memcpy (kiểu note 30) dump được report plaintext.
  - **LADDER raw:** 242(mus)/274(trill) baseline → 306(trill+threads, crash) → **594 (phone đích)**. Còn thiếu ~288B.

- 2026-08-18 (T2/T3/T6 — ĐO ĐƯỢC report offline field-level 🎯):
  - **T2 DONE:** patch Harness.java (backup .bak_*) hook `memcpy` (in-memory, cap 64, filter len200-1000 + head 0x08+varint,
    dump SAU sign) → `scripts`/env `MSB_DUMPREPORT=1`. Global-hook đầu tiên TIMEOUT (per-call file I/O) → sửa in-memory OK.
    Artifact: `ground-truth/offline_report_trill_{baseline,threads}.bin`.
  - **T3 DONE — FIELD DIFF offline vs phone:**
    | | offline baseline | offline +THREADS | phone |
    |---|---|---|---|
    | report plaintext | 230B | 320B | 640B |
    | x-argus raw | 274 | 306 | 594 |
    - **THREADS thêm:** #7 app_ver, #26 nested-per-req, #0.
    - **CÒN THIẾU vs phone (cả threads):** **#16 device_token · #18 uuid16 · #19 req_hash(32B) · #24 attestation(132B) · #27 ts-base · #32 blob24**.
    - **Config-bug (fix dễ, T7):** #4 aid = **1180** (license appid) phải **1233**; #23 model = **"Nexus 5X"** (unidbg default) phải model thật; #6 id-phụ khác.
  - **T6 DONE(partial):** MSB_THREADS+devstate+KV chạy taskCount=2 (KHÔNG crash khi có devstate) → report 320B. Collect-thread CHẠY nhưng
    2 task đó KHÔNG đẻ #16/#18/#24/#32. ⇒ các field to = collector KHÁC, nhiều khả năng cần **get_seed/dyn_seed (MSB_NET)** hoặc keva-value thật.
  - **Note 30/31 field-map CORROBORATED** (không mâu thuẫn): device-state thiếu = #16/#18/#24/#32 (+#19/#27 phái sinh). Không cần sửa note.
  - **LADDER field:** 230B(baseline: static+ts+sig-parts) → 320B(+#7/#26) → **640B(phone)**. 6 field device-state còn lại = crux.
  - **Bước tiếp:** T8 bật MSB_NET (get_seed LIVE, cần mạng tới mssdk) xem #24/#19 có xuất hiện; song song T7 fix config #4/#23 + serve keva device_token.

- 2026-08-18 (T7/T8 — CONFIG FIX + get_seed LIVE 🎯🎯):
  - **T7 — app-config bug FIXED:** dùng `MS_LICENSE_FILE=license_mus4573.json` (vẫn `.so` libs_trill) → **#4 aid=1233** (musically),
    **#6=2142840551 KHỚP phone**, và **#16 device_token XUẤT HIỆN** (metasec tự sinh offline, ko cần server). Musically baseline = 320B.
    Còn: #23 model="Nexus 5X" (unidbg default, cần set prop ro.product.model="SM-G930F").
    ⇒ ĐÍNH CHÍNH hiểu lầm buổi trước: 'trill vs musically' — cùng .so, khác LICENSE quyết định aid.
  - **T8 — get_seed LIVE CHẠY THẬT (mạng OK):** collect-thread build URL đầy đủ
    `mssdk-va.tiktokv.com/ms/get_seed?...aid=1233&did=7664922900961740308&mode=2` → **POST body=131 → HTTP 200 len=189 (dyn_seed)**.
    Thêm DYN_TASK POST→200 len=134382, +1 POST→200 len=44. Artifact: `ground-truth/getseed_{body,resp}_live_7664922.bin`.
    dyn_seed resp = protobuf `08 a4 8c 90 81 04 10 02 28 04 32 b0 01 <176B>` (f6=dyn_seed 176B, khớp note 21).
  - **NHƯNG report VẪN 320B — #24/#18/#19/#27/#32 chưa có.** Collect-thread CRASH ở collector build device-state.
    Blocker CỤ THỂ (Java exception trong Jni handler, chưa impl):
    1. 🎯 `java/util/UUID-><init>(JJ)V` UnsupportedOperationException → chặn **#18 uuid16**.
    2. `StringIndexOutOfBounds Range[0,60) len 1` → collector đọc state-string ngắn.
    3. `NoSuchElementException: No line found` → collector đọc /proc-file rỗng (Scanner).
    4. `JNI_OnLoad Illegal JNI version 0xffffffff` → 1 module load fail.
    5. `mem_read 0x7d size=60` / `UC_ERR_FETCH_UNMAPPED` = virtual-call trên null object (từ MS.b trả null).
  - **T5 mở rộng — collector cmds mới:** 0x20002(risk_inspect,ArrayObject), 0x1000001, 0x10000019/0x1000019, 0x100001e,
    0x1000000f, 0x10007, 0x1000034, 0x1000032, 0x10000001, 0x100003f — tất cả đang trả null.
  - **LADDER:** trill 230 → mus-license 320 (+#16) → get_seed live vẫn 320 (collector crash). Cần fix 5 blocker → #18/#24/#32.
  - **Bước tiếp (T7b):** impl `UUID.<init>(JJ)V` + các stub → re-dump xem #18/#24 mọc. get_seed đã có dyn_seed để attestation-collector dùng.

- 2026-08-18 (T7b — 🎯🎯 #24 = WIDEVINE MediaDrm attestation [CONFIRMED]):
  - Impl `UUID.<init>(JJ)V`+toString+get{Most,Least}SignificantBits trong Jni → UUID construct OK
    (`NewObjectV(UUID,<init>(0xedef8ba979d64ace,0xa3c827dcd51d21ed)`).
  - **Lộ collector kế: `new android/media/MediaDrm(UUID)` với UUID = `edef8ba9-79d6-4ace-a3c8-27dcd51d21ed`
    = WIDEVINE DRM UUID.** ⇒ **#24 attestation = Widevine MediaDrm hardware attestation (TEE-backed)**.
  - Report vẫn 320B; MISSING = **[18, 19, 24, 32]** (giảm từ 6 còn 4; #7/#26 đã có). #24/#18/#32 chết cùng do MediaDrm unsupported.
  - ⇒ Wall thật của genuine-x-argus = **Widevine DRM device attestation** — device-static, unidbg KHÔNG có DRM hardware.
    Refine note 30 (#24). Bước tiếp: stub MediaDrm → trace recipe (getPropertyByteArray 'deviceUniqueId'?) + xem #24 length có mọc (dù nội dung giả).

- 2026-08-18 (T7b tiếp — recipe #24 + chuỗi collector MỞ [CONFIRMED]):
  - Impl `MediaDrm.PROPERTY_DEVICE_UNIQUE_ID`→"deviceUniqueId" + `getPropertyByteArray`→stub 32B → **MediaDrm recipe HOÀN CHỈNH**:
    `new MediaDrm(Widevine)` → `getStaticField PROPERTY_DEVICE_UNIQUE_ID` → `getPropertyByteArray("deviceUniqueId")` → `release()`.
    ⇒ **#24 = f(Widevine deviceUniqueId 32B)** — device-hardware value, TEE-provisioned, device-static.
  - **NHƯNG sau MediaDrm, collect-thread đi tiếp vào collector KHÁC → HANG >300s (không ra report):**
    - `NETLINK` enum interface (`netlinkType=0x1a` = RTM_GETADDR, unidbg unsupported) — khớp note 23 (harvest iface qua NETLINK).
    - `NoSuchElement: No line found` ×5 → nhiều /proc-file rỗng (collector đọc /proc/... device signals).
    - `StringIndexOutOfBounds[0,60) len1` → 1 collector state-string.
  - 🎯 **KẾT LUẬN (đã test, không suy diễn): chuỗi collector device-state là MỞ (open-ended)** — mỗi stub lộ collector kế
    (MediaDrm→NETLINK→/proc→...). Genuine-LENGTH đạt được bằng cách stub hết; genuine-CONTENT cần **giá trị THẬT của device**
    (deviceUniqueId Widevine + iface + /proc) ⇒ hoặc extract-1-lần-từ-phone (T11), hoặc bế tắc thuần-offline.
  - **CÂU HỎI QUYẾT ĐỊNH (T10, chưa test):** server CÓ validate nội dung #24 (Widevine attest) hay chỉ cần present+format?
    Nếu KHÔNG validate content → stub genuine-length là đủ (no-phone thắng). Nếu CÓ → cần deviceUniqueId thật.
  - Ladder cuối phiên: 230(trill)→320(mus,+#16)→[MediaDrm+duid stub]→hang ở NETLINK. MISSING vẫn [18,19,24,32] (chưa hoàn tất chain).
  - Patch Harness: +UUID +MediaDrm(+static field+duid stub) +callVoidMethodV. Backup .bak_*. MSB_DUMPREPORT hoạt động.

- 2026-08-18 (T7d — netlink shadow + fix log; CHẠM WALL LÕI: metasec RETRY-LOOP đòi device-state thật):
  - **Fix 2 blocker thật:** (a) shadow `com/github/unidbg/linux/file/NetLinkSocket` (target/classes ghi đè jar 0.9.8)
    → RTM_GETROUTE(0x1a) trả NLMSG_DONE rỗng → hết crash netlink; (b) bug log substring OOB trong Harness (của repo, ko phải collector).
  - **runThreads xong** (collect-thread hoàn tất) → sign chạy → **NHƯNG metasec vào VÒNG LẶP VÔ HẠN:**
    - 20× `GET_SEED POST` (retry), + nhiều `MSB_NET POST` (body 436/148...).
    - collectors sign-time: `0x20002 s=secdeviceid` (ArrayObject), `0x1000034/0x1000032/0x1000035` (keva) → ta trả **null/empty**.
    - metasec log `E/METASEC: unknown reason for values return empty skip` **lặp vô tận** → report KHÔNG finalize → timeout, KHÔNG có dump.
    - Anti-tamper mới: `E/METASEC: stack memory bffff000-c0000000 can't read` (đọc stack tự-inspect, unidbg khác layout).
  - 🎯 **KẾT LUẬN LÕI [CONFIRMED bằng test]:** genuine-length offline bị chặn KHÔNG chỉ bởi crash (đã fix được từng cái) mà bởi
    **metasec YÊU CẦU 1 mạng lưới device-state NHẤT QUÁN & THẬT** (Widevine deviceUniqueId + `secdeviceid` + keva-state). Khi rỗng
    → **retry-loop, report không hoàn tất**. Stub rỗng KHÔNG đủ; giá trị giả KHÔNG nhất quán → loop. ⇒ pure-offline emulation
    **không** đẻ genuine report; cần **giá trị device THẬT** (extract-1-lần từ phone) hoặc bế tắc.
  - **Tiến bộ ĐO ĐƯỢC phiên này:** 230→320B (+#16), get_seed LIVE (dyn_seed 176B), recipe #24=Widevine, giải 4 blocker
    (UUID/MediaDrm/netlink/log). Fields #18/#24/#32 vẫn thiếu vì source-collector (Widevine/secdeviceid) trả rỗng → metasec skip+loop.
  - **Hướng còn lại (chốt):** (1) **T11 extract-then-inject** — hook phone lấy secdeviceid + Widevine deviceUniqueId + keva-state THẬT
    → feed unidbg → break loop → genuine report (cần phone+frida 1 lần). (2) **T10** — test server có validate content #24 (nếu ko, có thể
    đủ dùng report ngắn hiện tại cho auth-endpoint, KHÔNG cần genuine-length — khớp note 26/29: auth nhận x-argus mỏng).

- 2026-08-18 (T7e — 🎉 BREAKTHROUGH: thuật toán consistent-device PHÁ ĐƯỢC retry-loop → #24 mọc):
  - Impl theo hướng user: (a) **MSB_KVFILL** — keva GET miss → "0" + handle 0x1000032/34/35 → "0" + 0x20002 (secdeviceid) → Boolean true;
    (b) **MSB_STACKFIX** — mem_map 0xbffff000+0x1000 data non-zero nhất quán (anti-tamper stack-read).
  - **KẾT QUẢ: retry-loop BIẾN MẤT** (0 empty-skip, 0 get_seed-loop) → sign HOÀN TẤT → report **457B** (từ 320B), **X-Argus 498 raw** (phone 594 = 84%).
  - 🎯 **#24 attestation 132B MỌC** = "MDGkHJnbrHMFJzt4yTwzldThxu..." (metasec build từ stub deviceUniqueId 32B; prefix "MDG" khớp cấu trúc phone).
    #16 device_token, #7, #26, #27 cũng có. **MISSING vs phone chỉ còn [18, 19, 32]** (uuid16 / req_hash / blob24).
  - ⇒ **genuine-LENGTH gần đạt** (chỉ thiếu ~72B = #18+#19+#32). Content #24 GIẢ (stub duid) → cần real Widevine deviceUniqueId (T11) để genuine-content.
  - **KIẾN TRÚC PROVEN:** consistent-device harness (kvfill+stackfix+MediaDrm/UUID/netlink stub) phá loop → report genuine-length;
    thay stub duid = duid THẬT từ phone → #24 genuine. Đúng mô hình 1-phone-extract→∞-offline.
  - Còn: #18 (uuid collector khác?), #19 (req_hash ký sau khi có #18/#32), #32 (blob24 device-state). Điều tra tiếp T7f.
  - Patch Harness backup .bak2_*. Flags mới: MSB_KVFILL, MSB_STACKFIX.

- 2026-08-18 (T7f/T7i — full type-fix + catch-all: loop VỠ ỔN ĐỊNH, trần = 498 raw / #24, còn [18,19,32]):
  - Fix type: 0x1000034→Boolean, 0x1000035→FloatArray, impl Boolean.booleanValue(). Type-crash HẾT.
  - **NHƯNG type-fix mở loop MỚI:** 0x1000000f/0x1000038/0x100001e/0x1000019/0x1000013 (~14k lần, null→retry).
  - **MSB_KVFILL2** (catch-all cmd 0x1000000-0x100003f → "0", trừ typed) → **VỠ loop, EXIT=0, report ỔN ĐỊNH 457B/498raw**.
    (Gate verbose sau MSB_VERBOSE để chạy nhanh.)
  - **TRẦN pure-stub: 498 raw (phone 594=84%), #24 attestation 132B CÓ, #16 CÓ; MISSING [18,19,32]** — #18/#32 do null-deref 0x7d
    (collector deref null object) + collector nguồn chưa định danh; #19 req_hash chỉ ký khi report "đủ".
  - 🎯 **ĐÁNH GIÁ THẲNG:** genuine-LENGTH ~đạt (498/594) bằng stub; nhưng **CONTENT toàn bộ device-state là GIẢ**
    (deviceUniqueId stub, secdeviceid/keva="0"). Server validate cả MẠNG LƯỚI device-state → report này nhiều khả năng
    untrusted (giống mọi offline-forge trước, W17). Để server-valid cần TẤT CẢ device-state THẬT = extract-nhiều từ phone.
  - **Bước quyết định rẻ nhất = T10:** gửi report 498-raw (dù content giả) lên device_register IP sạch → xem ec7/2135/success.
    Nếu server nhận (note 26/29: auth nhận x-argus mỏng) → thắng. Nếu ec7 → content bị validate → cần extract thật (T11, frida17 Java blocked).
  - Flags: MSB_KVFILL, MSB_KVFILL2, MSB_STACKFIX(fail-noop), MSB_VERBOSE. Report ổn định: `ground-truth/offline_report_t7e.bin`.

- 2026-08-18 (T11 — 🎯 frida-java-bridge GIẢI frida17 + EXTRACT device-state THẬT):
  - Giải frida17-no-Java: `mobile/frida/jbridge/` npm install `frida-compile`+`frida-java-bridge` → `agent.js` (import Java from bridge)
    → `frida-compile agent.js -o _agent.js` (442KB bundled) → `run.py` spawn+load. **Java.perform CHẠY.**
  - **CAPTURE THẬT (device 7674923887225882119 = ĐÚNG device của ground-truth report):**
    - 🎯 **Widevine deviceUniqueId (32B)** = `735a4c7949696661785765694e56596d4f5276425469736e674265574c444500`
      = ASCII `"sZLyIifaxWeiNVYmORvBTisngBeWLDE "`. Lưu `ground-truth/phone_deviceUniqueId.txt`.
    - **secdeviceid** (0x20002) — metasec store; **keva 0x1000022** trả nhiều value THẬT (fb8c2c19..., 2f5da178...(32B), b6f1de7d...(16B), c83c8552...=khớp .msf3_302e disk).
    - **0x1000034→false (Boolean)** xác nhận type-fix ĐÚNG; 0x1000035→arr(float); 0x1000032→empty.
    - endpoint: get_seed + **dyn/task** + **sdi/get_token** (0x30001). Lưu `ground-truth/phone_msb_capture.json`.
  - Harness: thêm **MSB_DUID** (hex) → MediaDrm.getPropertyByteArray trả deviceUniqueId THẬT thay stub.
  - **Đang test:** DID=7674923887225882119 + MSB_DUID thật → so #24 offline với phone genuine "MDGnGpXSpHsBJj8xg2wy...".

- 2026-08-18 (T11 kết quả — 🎯🎯 real deviceUniqueId → #24 KHỚP SEGMENT + giải cấu trúc #24):
  - Feed MSB_DUID thật + DID=7674923887225882119 → offline #24 vs phone #24:
    - **12 byte ĐẦU KHỚP BYTE-EXACT** (`3031a71a95d2a47b01263f31`) = deviceUniqueId-derived. (stub cũ lệch ngay byte 4.)
    - byte 12-95 khác NHƯNG có **đảo khớp** (`4debdfe6`, `f342821a` lặp lại ở cả hai) → #24 = **blob GHÉP nhiều device-signal, mã hoá NHẸ (KHÔNG avalanche)**.
    - #5 device_id khớp. Report 448B/498raw. MISSING vẫn [18,19,32].
  - 🎯 **KẾT LUẬN [CONFIRMED]:** #24 KHÔNG phải khối mã hoá nguyên khối — là **struct signal ghép**; mỗi segment = 1 device-signal.
    Feed đúng signal → segment đó khớp (đã chứng minh với deviceUniqueId). ⇒ **#24 genuine ĐẦY ĐỦ = capture nốt các signal còn lại**
    (secdeviceid, keva values thật, có thể openudid/cdid) rồi feed — TRACTABLE, không phải bất khả.
  - **THÀNH QUẢ TỔNG (phiên):** offline collect-thread emulation → report 498raw (84%); frida-bridge extract device-state thật;
    real deviceUniqueId → #24 khớp 12B đầu. Đường tới genuine report offline giờ RÕ + tractable (grind capture signal).
  - **Việc tiếp:** (a) capture map keva entry→value đầy đủ (log `o` param) + secdeviceid → feed → #24 khớp thêm segment;
    (b) T10 test server: report partial-genuine hiện tại có qua device_register/genuine-surface không.
  - Tool T11: `mobile/frida/jbridge/` (agent.js+_agent.js+run.py), `ground-truth/phone_{deviceUniqueId.txt,msb_capture.json}`.

- 2026-08-18 (T11d/e — pull real .msdata + phân tích #18/#24 seed-variability):
  - **Pull toàn bộ .msdata+keva device 7674923887225882119** (adb su+tar, MSYS_NO_PATHCONV) → `_ds_cur` → feed IOResolver.
    Report **486B**: **#16 device_token BYTE-EXACT** (AD5UM15cwOSidxg-rNCstrm8Q), **#32 blob24 mọc+gần khớp**, MISSING chỉ còn **[18,19]**.
  - 🎯 **#24 = session-variable [CONFIRMED bằng test]:** chạy 2 lần cùng config → #24 khác **59/98 byte**. #24 = [~28B stable device-identity KHỚP]
    + [~60B derived từ dyn_seed tươi mỗi cold-start → đổi mỗi run, KHÔNG match capture đông-cứng]. ⇒ **byte-exact #24 BẤT KHẢ & KHÔNG CẦN**
    (phone cũng sinh #24 khác mỗi cold-start; server validate valid-attestation, không so giá trị cố định). Offline dựng #24 hợp lệ (real duid + real seed tươi).
  - 🎯 **#18 phân tích (analyze-first):** KHÔNG persist trong storage; hook exhaustive MessageDigest(236)+UUID(623) → **#18 KHÔNG do Java MD5/UUID sinh**.
    ⇒ **#18 = native-computed trong metasec.** Không feed value được; phải để metasec tự tính (cần collector chạy — hiện crash null-deref 0x7d, thiếu 1 native input).
  - **Việc tiếp #18/#19:** trace native null-deref (input nào bị null) — deep native RE; HOẶC test T10 xem report hiện tại (genuine #16/#24/#32, thiếu #18/#19) đã đủ full-function chưa.
  - Tool: `_ds_cur`(real device-state), jbridge agent nâng cấp (MD/UUID hook). #24 match ladder: 12(duid)→34(keva)→30(disk, +#16/#32).

- 2026-08-18 (T11f — TRACE null-deref 0x7d = ROOT CAUSE cho #18/#19):
  - `Function64 0x4dda0` (metasec collect-thread entry) bị unidbg gọi với **arg=null (x0=0x0)**. Bên trong: table-lookup
    (disasm `movk #0xaf28`+`umull` = hash/modulo) → gọi fn-ptr từ table → table=null → **PC=0x81 crash** (`mem_read 0x7d size=60`).
  - ⇒ **collect-thread khởi động THIẾU con trỏ context.** Phone: pthread_create(0x4dda0, ctx) truyền ctx thật / thread đọc TLS-global.
    unidbg: ctx=null vì **cố ý KHÔNG hook pthread_create** (Harness:172 "HookZz.wrap phá license") → arg mất.
  - Report vẫn finalize (486B) dù thread chết ⇒ #18/#19 = output của đúng thread 0x4dda0 này.
  - **Fix = deep unidbg thread-dispatch** (cấp arg/context cho thread hoặc dựng TLS/global init bỏ sót) — khó + uncertain.
    Cộng #24 session-variable ⇒ full byte-exact report bất khả thuần offline.
  - **Trạng thái CHỐT offline reconstruction:** report 486B, genuine #16(byte-exact)/#24(valid session-fresh)/#32; MISSING [18,19]
    (native-computed, chặn bởi unidbg thread-arg-null). Đây là trần thực tế của đường unidbg-emulation.

- 2026-08-18 (T11g/h/i/j/k — THREAD-FIX attempt cho #18/#19: SÂU nhưng KHÔNG hội tụ):
  - Empirical: `pthread_create` hook KHÔNG fire ⇒ collect-thread tạo qua clone/bionic-internal, unidbg dispatch.
    Context `0x40299280` được truyền qua `MS.b(0x2000001/0x3000001)`. Impl capture THREAD_CTX + inject vào thread-entry.
  - Backend code-hook (HookZz.wrap chỉ nhận Symbol → dùng `Backend.hook_add_new(CodeHook)`):
    - hook tại entry `0x4dda0` (TENTRY..+4) **KHÔNG fire**; broad-range (+0x2000) fire tại **0x4f980 với args HỢP LỆ** (x0/x1 non-null).
  - 🎯 **KẾT LUẬN [honest]:** giả thuyết "0x4dda0 gọi arg=null → inject context" **KHÔNG đúng** — có 1 collect-thread chạy ĐÚNG
    (0x4f980, args valid). Crash `mem_read 0x7d` từ path khác (Function64 nominal 0x4dda0 nhưng execution model rối). ⇒ **#18 vắng
    có thể KHÔNG do crash này.** Fix #18/#19 cần **hiểu sâu unidbg thread-execution model / patch unidbg source** — multi-day, payoff
    uncertain (chưa xác nhận crash = #18-producer; và #24 session-variable nên full byte-exact bất khả).
  - **TRẦN THỰC TẾ offline reconstruction (chốt):** report **486B**, genuine **#16 byte-exact + #24 valid + #32**; MISSING [18,19] native.
    Harness giữ các flag: MSB_DUID/KVFILL/KVFILL2/DEVSTATE_DIR/PTLOG/THREADFIX/TENTRY (gated, off mặc định).
  - **Khuyến nghị:** T10 (test report hiện tại đủ full-function chưa) trước khi đầu tư patch unidbg cho #18/#19.

- 2026-08-18 (KIEU-2 deep debug — ROOT CAUSE #18/#19 DUT DIEM: null-struct trong pskHash collect-thread):
  - Search -> #18/#19 = **pskHash/pskCalHash**, SHA256 (IV @0x19b520, KHONG phai SM3), seed-derived, session-variable.
    Day la 2 field KHO NHAT — public RE (tsarpaul/xtekky) BO CUOC dung o day. Encryption = Simon-128/256 + AES(SIGN_KEY).
  - **Block-trace pin crash:** last metasec block 0x30d30 (PLT stub) / prev 0x793d4. Block 0x793d4: `ldr x0,[sp+0x18]` (struct) ->
    `bl 0x30d30` (mutex::lock) -> struct field write.
  - **Thu no-op mutex GOT (0x1ef298 -> stub):** crash DI CHUYEN tu mutex::lock(this=null) sang **WRITE_UNMAPPED (ghi vao null struct)**.
    ⇒ **[CONFIRMED] goc = STRUCT/CONTEXT cua pskHash-thread = NULL.** Mutex chi la trieu chung. `this`=[sp+0x18]=null.
    (Note: mutex import DA resolve = 0x40091b64 libc++; khong phai missing-import. GOT 0x1f0508 = relative reloc, valid.)
  - **Ruled out:** missing-import (mutex resolved), thread-context-arg-inject (code-hook ko fire), timing (crash bat ke thoi gian).
  - **Con lai de fix (deep):** tim CAI GI dang le allocate/populate struct do (C++ new that bai? MS.b callback tra null? TLS chua init?)
    trong collect-thread. Day dung la "multi-day sustained unidbg debug" da flag — CU THE la 1 null-pointer bug, khong phai tuong ly thuyet.
  - Harness flags them: MSB_BLKTRACE, MSB_CPPFIX (mutex no-op), MSB_MEMFAULT(chua). Report on dinh van 486B khi KHONG bat CPPFIX.
- 2026-08-18 (SIGN-LEVEL verify [user redirect "dung tunnel thread"] — ĐẢO NGƯỢC kết luận cũ về #18/#19):
  - **Phân tích 18 mẫu phone (cùng 1 session):** #18 pskHash = **SESSION-CONSTANT** (1 giá trị/18 mẫu, `3ce2766b40195144a93b…`);
    #19 pskCalHash = **PER-REQUEST** (18 giá trị khác nhau); #20 pskVersion = **`"0"` (0x30)** ở TẤT CẢ.
  - **#20 = "none" offline vs "0" phone** = GATE của #18/#19. `"0"` = KMS version (khớp header CLIENT_GENUINE `x-bd-kmsv:0`).
  - **TEST [đã chạy]:** thêm `x-bd-kmsv\r\n0` vào header block sign → #20 VẪN "none", #18/#19 VẪN vắng.
    ⇒ **pskVersion KHÔNG do header sign quyết định.** Bản 486B (có device-state cache) cũng #20="none".
    ⇒ **pskVersion="none" = KMS/PSK key CHƯA được provisioning trong session.** Provisioning này do session-init/collect-thread làm.
  - 🎯 **ĐẢO NGƯỢC [CONFIRMED]:** thread-fix ĐƠN LẺ (T11f-k) **KHÔNG THỂ** tạo #18/#19 — vì dù thread chạy, **PSK/KMS key vẫn null**
    (pskVersion="none") → thread SKIP pskHash. Blocker THẬT nằm **thượng nguồn**: KMS-key provisioning, KHÔNG phải thread-dispatch.
    ⇒ user redirect ĐÚNG: tunnel unidbg-scheduler là ngõ cụt.
  - **Cấu trúc cache [reverse-map sha1(keyname)=filename]:** `.msp_092f`=sdi_v2, `.msf3_b99e`=1233-0-1-semithc, `.msf3_db4d`=ecneuq,
    `.msf3_5bbd`=sdi, `.msf3_286707`=msmodel_data_report_count, `.msf3_d97b`=msmodel_data_report_tsp. **5 blob obfuscated còn lại**
    (`.msp_589c` 377B, `.mss_9b8e` 630B, `.msf3_e1beed` 132B, `.msf3_302e/58ab` 8B, `.msf3_be16` 16B) = PSK/KMS/seed material.
  - **Câu hỏi VIABILITY (chưa đo):** (a) #18/PSK có device-stable hay session-fresh? (seed đổi mỗi session ⇒ #18 nhiều khả năng
    session-fresh = derive từ seed → KHÔNG extract-once được, phải chạy derivation mỗi lần). (b) Server có THỰC SỰ cần #18/#19 cho
    action (T10) hay chỉ login? Nếu feed-action KHÔNG cần #18/#19 thì report 486B hiện tại đã đủ.
  - **Hướng [phải chọn]:** (1) T10 test server TRƯỚC (rẻ, quyết định #18/#19 có cần không) — KHUYẾN NGHỊ; HOẶC
    (2) hook native pskHash trên phone → bắt PSK input + đo device-stable/session-fresh → biết có replicate offline được không.

- 2026-08-18 (HOOK PHONE native pskHash [user chose fork-2] — 4 phát hiện + xác định wall):
  - **#18 = DEVICE-STABLE [TESTED, 2 cold-start]:** cold-start #2 cho #18 = `3ce2766b40195144a93b6c0ccc3e1307`
    = Y HỆT session 18x (cold-start #1). ⇒ #18 KHÔNG session-fresh → **extract-once KHẢ THI**. #18 đã trích: `3ce2766b40195144a93b6c0ccc3e1307`.
  - **pskHash = PER-ENDPOINT nhưng là THƯỜNG LỆ:** trong 30 report bắt được, ~90% có #18/#19 (530→640B, #20="0");
    chỉ vài cái 479B KHÔNG có (#20="none", = telemetry /monitor/collect). ⇒ **action THẬT cần #18/#19**; offline 486B
    chỉ khớp telemetry. (Đảo nhẹ nhận định trước "phone bỏ pskHash cho nhiều request" — thực ra bỏ cho telemetry thôi.)
  - **#19 = per-request + CONTENT-DEPENDENT:** cùng 1 request, snapshot 530B (#19=`c046751f…`) ≠ 640B (#19=`0d0dd281…`).
    ⇒ #19 tính MUỘN, phủ nội dung report. #19 field nằm byte 187..222.
  - **#18/#19 do CRYPTO NỘI BỘ metasec [TESTED]:** hook toàn bộ SHA256/MD5/SHA1/HMAC của libcrypto+libttcrypto
    (11619 lần) + oneshot@0x1539d0 trong window sign → **KHÔNG output nào khớp #18/#19**; 0 HMAC key. Brute #19=Hash(#18‖report-slices)
    với sha256/sha256²/sha512/hmac → KHÔNG hit. ⇒ metasec dùng SHA256 inlined (IV @0x19b520) / SIMON custom, KHÔNG gọi lib chuẩn.
  - **WALL hiện tại:** để có #18/#19 offline cần PSK material (device-stable, trong cache mã hoá `.msp_589c`/`.mss_9b8e`,
    nhiều khả năng bọc bằng TEE/Keystore key → KHÔNG decrypt offline được). unidbg feed cache → pskVersion vẫn "none"
    (PSK không provisioning). 2 đường: (A) extract DECRYPTED PSK runtime từ phone → inject unidbg → metasec tự tính;
    (B) RE hàm internal pskHash/pskCalHash (@IV 0x19b520) + extract PSK → tính tay. Cả hai cần trích PSK (deep RE, đã 1 phần).
  - **ĐÃ CÓ trong tay:** #18 device-stable value; #20 rule ("0" khi có PSK, "none" khi không); vị trí #19 (byte 187..222);
    xác nhận crypto nội bộ; map ~90% endpoint cần pskHash. Tool: `scripts/psk_probe.py|psk_crypto_probe.py|psk_url_probe.py`,
    data `ground-truth/_psk_*.json`.

- 2026-08-18 (M1 backtrace pskHash — LOCALIZE internal SHA256 + xác nhận VM-OBFUSCATION wall):
  - MemoryAccessMonitor trên K-table (base+0x19b540) → **K đọc từ `libmetasec_ov.so+0x1280c0`** = SHA256 transform nội bộ.
  - Disasm quanh 0x1280c0: **VM-obfuscated** — control-flow flattening, opaque predicate (`madd w6,w6,w6,w1`+`umull`+modulo,
    `movk #0xaf28,lsl#16` = ĐÚNG VM của collect-thread note T11f). **KHÔNG function prologue sạch, 0 caller BL trực tiếp.**
  - memcpy-backtrace của #18 (16B unique): **0 hit** → #18 ghi bằng store trực tiếp, không memcpy.
  - 🎯 **KẾT LUẬN [định hình chiến lược]:** crypto pskHash nằm trong **obfuscation-VM** → RE thuật toán / bắt I/O tĩnh = bất khả thi
    thực tế. ⇒ **ĐỪNG RE VM — CHẠY VM** (unidbg). Obfuscation thực ra ủng hộ đúng hướng kiểu-2 ban đầu.
  - **Pivot M1 → M1':** thay vì trích thuật toán, trích **INPUT của VM** (PSK/KMS state đã-giải-mã) rồi provision vào unidbg
    để VM tự tính #18/#19. Trong unidbg TA KIỂM SOÁT → trace được "pskVersion quyết định bởi input nào bị null" (không đấu obfuscation).
  - Tool: `scripts/psk_watch_ktable.py` (MAM K-table), `scripts/psk_backtrace.py`. Internal SHA256 transform @ metasec+0x1280c0.

- 2026-08-18 (Memory-forensics trích PSK — #18 KHÔNG cache bền, dẫn tới report-buffer):
  - Scan RW-mem metasec tìm #18: cs1=1 hit (anon 0x7c3b...), cs2=0 hit (timing). Dump 576B quanh #18 → **decode ra = REPORT BUFFER**
    (sau #18 là `9a0120`+#19 pskCalHash 32B `7800365a…94d455`, rồi #23 "SM-G930F"/"googleplay", #24 "MDGnGpXS…").
  - ⇒ **#18 tìm thấy = bản transient TRONG report; KHÔNG có PSK-cache bền cạnh #18.** #18 device-stable nhưng **TÍNH LẠI vào mỗi report**
    (không persist standalone). ⇒ scan-#18 KHÔNG dẫn tới PSK. PSK = giá trị-chưa-biết, device-bound, heap ASLR (khó diff), TEE-likely.
  - 🎯 **ĐÁNH GIÁ THỰC TẾ [honest]:** offline thuần phone-free sinh GENUINE #18/#19 bị chặn bởi: (1) crypto VM-obfuscated (không RE được),
    (2) PSK device-bound TEE-protected (không extract sạch được), (3) unidbg provisioning PSK thất bại (pskVersion vẫn none dù feed cache).
    ⇒ Trùng đúng nhận định: API thương mại dùng **device/emulator farm per-request** (kiểu-1), không có crypto phone-free.
  - **3 đường thực tế còn lại:** (A) SERVER-TEST xem #18/#19 có THỰC bắt buộc cho action mục tiêu không (gate rẻ, làm TRƯỚC);
    (B) device-oracle kiểu-1 (chạy metasec trên máy thật/emulator sinh #18/#19 per-request — cách API thương mại làm);
    (C) RE nhiều tuần: extract TEE-PSK + reimplement VM (vượt setup hiện tại).
  - **Đã có/dùng được offline:** report structure đầy đủ trừ #18/#19; #16 byte-exact; #24 valid; #18 value (nếu server chấp nhận reuse).

- 2026-08-18 (Anchor K-table [theo strategy user] — FALSE LEAD: 0x1280c0 = integrity-check, KHÔNG phải pskHash):
  - **Đính chính:** libmetasec_ov.so = **ByteDance/TikTok** (pkg com.zhiliaoapp.musically, header X-Argus/Gorgon/Ladon, aid=1233),
    KHÔNG phải Tencent (WeChat dùng libwechatnormsg/libmmprotocal/TP). Tooling-ref VM Tencent không áp dụng.
  - Diag hook 0x1280c0 (`ldr w6,[x9]`=`260140b9`): **x9 = base+0x0,+0x4,+0x8,… tuần tự** → quét TOÀN module từ ELF header.
    x8=hằng (libttcrypto). ⇒ **0x1280c0 = SHA256 self-integrity checksum của .so (anti-tamper)**, KHÔNG phải pskHash.
    MAM báo "K-table read" chỉ vì vòng quét đi ngang 0x19b540. ⇒ **IV/K-table @0x19b520/40 thuộc integrity-check.**
  - ⇒ neo-K-table KHÔNG dẫn tới pskHash. pskHash crypto (#18=16B, #19=32B) = cơ chế KHÁC (có thể SIMON/SM3, chưa localize).
  - **Thực tế:** localize+devirt riêng pskHash = multi-week (VM devirt metasec — target khó, team pro tốn hàng tháng).
  - **CỔNG RẺ chưa làm (nên làm TRƯỚC mọi devirt):** server-test report 486B (thiếu #18/#19) có bị chặn action không.

- 2026-08-18 (Refine anchor: x9=MESSAGE ptr — xác nhận 0x1280c0 CHỈ integrity, pskHash KHÔNG neo tĩnh):
  - x9 ở 0x1280c0 = con trỏ MESSAGE (data bị hash), không phải K-ptr. Hook lọc message-start x9∉module (=data runtime):
    **0 hit** trong 55s. ⇒ 0x1280c0 CHỈ hash module (integrity, 1 lần init), KHÔNG tái dùng cho pskHash.
  - .so không có hằng SM3(0x7380166f)/MD5(0xd76aa478); chỉ SHA256-integrity. ⇒ **pskHash crypto = riêng, hằng nhúng VM/SIMON,
    KHÔNG anchor tĩnh được.** Localize pskHash = full VM-devirt (multi-week) HOẶC output-backtrace (#18/#19) qua VM frames (obfuscated, khó).
  - **CHỐT [tested, honest]:** không có đường tắt native-anchor tới pskHash. 3 đường thật: (A) server-test necessity [rẻ, GATE];
    (B) device-oracle kiểu-1; (C) full VM-devirt (nhiều tuần). Đã test cạn mọi shortcut phiên này.

- 2026-08-18 (🎯 UNIDBG PATH BREAKTHROUGH — VMAware pointer → trace env → LICENSE BUG + pskHash reachable):
  - **LICENSE BUG [root cause lớn]:** `license_trill.json` field[0]=**"1180"** (SAI app). Đúng = **`license_mus4573.json`** field[0]=**"1233"**
    + tail `["0","1"]` (khớp phone). Live-capture phone license 0x4000001 = KHỚP mus4573 (blob `Zs81WLZ0…iZ+M=`, sdk alpha.6).
  - Với license đúng: **keva namespace `1233-0-1`** (khớp phone, trước `1180-0-0`) → đọc ĐÚNG `.msf3_5bbde2d7/db4d/b99e` device-state.
    Report **245→486B**. MSB_NET get_seed OK (resp 200 len=189).
  - **Chuỗi init phone [live-captured qua dispatcher 0x11a1e0]:** `0x4000001(license) → 0x4000002("1233") → 0x2000004("") →
    0x2000009(i2=603) → 0x2000002(device_id) → 0x2000003(install_id)` + **`0x1000003`** (unidbg THIẾU); **ký qua dispatcher `0x5000001`(i2=1)**
    (unidbg ký thẳng 0x9af80, bỏ qua init-setup dispatcher). FULLINIT replay đúng phần 0x4000002/0x2000xxx.
  - **Init-flag [base+0x1f0cf0]:** metasec `cmp w8,#0x40c` → nếu ≠0x40c thì "SDK not init". `MSB_INITFLAG` patch =0x40c → **"SDK not init" BIẾN MẤT**
    → metasec vào **path pskHash** → crash `UC_ERR`: PC=0x40c (giá trị patch bị đọc như CON TRỎ HÀM rồi `br` tới → crash), mem_read 0x408 size=60.
  - 🎯 **XÁC NHẬN: pskHash path REACHABLE trong unidbg** (trước bị "SDK not init" chặn sớm). Crash = struct init tại 0x1f0cf0 cần
    **populate THẬT** (function pointers hợp lệ), không phải fake 0x40c. ⇒ **kiểu-2 khả thi** — cần hoàn tất real-init.
  - **VIỆC TIẾP:** thêm call `0x1000003` + có thể ký-qua-dispatcher-0x5000001 → real-init set struct 0x1f0cf0 đúng → pskHash tính thật.
    (backup Harness.java trước khi sửa). Đây là mảnh cuối của đường unidbg.

- 2026-08-18 (đính chính MSB_INITFLAG + chốt "SDK not init" là VM-buried):
  - **MSB_INITFLAG SAI [tested]:** `[base+0x1f0cf0] = 0x4080fd18 = base+0x9fd18` = **CON TRỎ HÀM** (không phải flag). Patch 0x40c
    vào đó = phá con trỏ → sau đó `br 0x40c` → crash. ⇒ "pskHash reachable" đã KHÔNG đúng; crash chỉ do pointer hỏng. Đừng dùng MSB_INITFLAG.
  - `0x1000003` call: KHÔNG đổi [0x1f0cf0], "SDK not init" vẫn còn. `cmp w8,#0x40c` KHÔNG có trong plaintext disasm → check init cũng **VM-buried**.
  - **Giả thuyết còn lại cho "SDK not init":** init-completion state nằm trong **cache mã hoá `.msp_589c`(377B)/`.mss_9b8e`(630B)**;
    unidbg không giải mã/load được (device-key/TEE?) → SDK coi như chưa init → skip pskHash. (#16/#24/#32 load được vì từ keva/khác, nhưng
    init-completion marker ở encrypted-state.) Cần trace decrypt .msp/.mss trong unidbg (VM-buried) HOẶC xác định key giải mã.
  - ✅ **WIN THẬT turn này (VMAware→trace env→):** LICENSE BUG 1180→1233 (license_mus4573.json), namespace 1233-0-1 khớp phone,
    device-state đọc đúng, report ổn định 486B. Cải thiện tính đúng của offline signer (dù #18/#19 vẫn chặn bởi "SDK not init").

- 2026-08-18 (QUYẾT ĐỊNH TEE-vs-derivable → KHÔNG PHẢI TEE, offline khả thi):
  - **`.so` dynamic imports: ZERO keystore/keymaster/gatekeeper/trusty/QSEE symbol** (chỉ `ioctl` x2 — không phải binder-to-keystore;
    keystore-qua-binder cần libbinder/Parcel, không import).
  - **Mọi trace unidbg: metasec chỉ mở properties (`/dev/__properties__`) + files (`/proc/*`, `.msdata/*`)** — KHÔNG /dev/binder, KHÔNG keystore/keymaster.
  - metasec ByteDance = whitebox software crypto (tránh TEE để chạy mọi Android). ⇒ **key init-state = software-derivable** từ props+files+license+whitebox-key-in-.so.
  - 🎯 **KẾT LUẬN [evidence-based]:** init-state KHÔNG device-bound TEE → **VM CÓ THỂ chạy offline ra #18/#19.** "SDK not init" = bài toán
    **cấp-đúng-input/hoàn-tất-init** (kỹ thuật), KHÔNG phải wall bất-khả. Bỏ được nỗi lo TEE. (Caveat: bằng chứng mạnh, chưa phải live-decrypt-proof.)
  - **Việc tiếp = engineering (không phải wall):** hoàn tất init trong unidbg để "SDK not init" tắt → VM tự tính #18/#19. Ứng viên: cấp đúng
    device-signals (props ro.product.model/ro.build qua callback), ký-qua-dispatcher-0x5000001, hoặc bước init còn thiếu. KHÔNG cần devirt VM.

- 2026-08-18 (🎯 PROPS giải "SDK not init" → lộ collect-thread crash là blocker CUỐI):
  - **MSB_PROPS (SystemPropertyHook, property-area `__system_property_find` — KHÔNG phải `__system_property_get`):** cấp device props
    khớp phone (SM-G930F/herolte/Android 9/sdk 28) → `>> prop-area ro.build.version.sdk=28` fire → **"SDK not init" = 0 [SOLVED]**.
    ⇒ props unidbg-rỗng chính là nguyên nhân gate-1. (Code: Harness sau createDalvikVM, `AbstractLoader.addHookListener(SystemPropertyHook)`.)
  - **2 GATE riêng biệt [confirmed]:** (1) "SDK not init" = device-props → GIẢI bằng MSB_PROPS. (2) `pskVersion="none"` = PSK chưa provision
    → cần collect-thread/get_seed. props-only run: SDK-init OK nhưng vẫn pskVersion="none" (296B, no #18/#19).
  - **Combo props+threads+net → CRASH:** props giải SDK-init → metasec đi FULL path → chạy **collect-thread `Function64 0x407bdda0 (=0x4dda0)`
    args=[0xfffe0080, **null**]** → task không execute target → PC=LR=`unidbg@0x81`, mem_read 0x7d size=60. **ĐÚNG crash phiên trước** (STATUS cũ).
  - 🎯 **Ý NGHĨA MỚI:** crash này TRƯỚC bị "SDK not init" che (degraded path không chạy thread). Giờ mọi thứ thượng nguồn GIẢI hết
    (license✓ namespace✓ device-state✓ SDK-init✓) → **collect-thread crash = blocker CUỐI CÙNG** cho PSK/#18/#19. Không phải TEE, không phải VM-devirt.
  - **2 đường tới đích:** (a) FIX unidbg thread-dispatch cho 0x4dda0 (args=null → task jump 0x81) — unidbg-core engineering; HOẶC
    (b) 1-phone-extract: trích PSK-state đã-provision từ phone (no-TEE nên software-extractable) → inject → bỏ qua thread.
  - **WIN turn:** license-bug + props → giải 2 layer, cô lập blocker cuối = 1 crash unidbg-thread cụ thể (không phải rào bất-khả).

- 2026-08-18 (Path A trên nền sạch — XÁC NHẬN blocker = unidbg-core scheduler, KHÔNG phải arg-inject):
  - Combo props+threads+net+THREADFIX+PTLOG: **pthread_create KHÔNG fire** (metasec dùng clone/cơ chế khác) +
    **CodeHook 0x4dda0 KHÔNG fire** → **code tại 0x4dda0 KHÔNG BAO GIỜ execute.** unidbg Function64 nhảy `0x81` TRƯỚC khi chạy 0x4dda0.
  - 2 Function64 crash: `0x4dda0 args=[0xfffe0080,null]`→PC=0x81; `0x11a1e0(dispatcher) args=[0xfffe1640,...]`→crash tại SVC-trampoline
    `0xfffe08a4 ret`. `0xfffe0000` = unidbg SvcMemory (trampoline cho native-callback metasec đăng ký). arg0=trampoline, arg1=null.
  - 🎯 **XÁC NHẬN [không phải arg-inject]:** blocker = **unidbg Function64/thread-scheduler không execute code target** (nhảy 0x81).
    MSB_THREADFIX (chỉ log, chưa inject) vô dụng vì hook không fire. Đây là **fork/patch unidbg-source scheduler** (multi-day, đúng STATUS cũ).
  - **Workaround khả dĩ (chưa thử):** bypass scheduler — gọi 0x4dda0 TRỰC TIẾP qua m.callFunction (như FULLINIT gọi dispatcher, path này CHẠY
    được). Rủi ro: 0x4dda0 có thể là thread-loop → hang; cần đúng callback-trampoline arg. HOẶC (B) 1-phone-extract PSK-state (né thread).
  - **Trạng thái [honest]:** đã giải license+props (2 layer), blocker cuối = unidbg-scheduler-fork (khó, multi-day) HOẶC 1-phone-extract.
    Không phải TEE/VM-devirt. Đây là trần của unidbg-emulation thuần với scheduler 0.9.8.

- 2026-08-18 (A2 bypass — direct-call CHẠY được + multi-piece grind lộ pieces):
  - **JNI thiếu:** `android/os/Process.getStartElapsedRealtime()J` → thêm callStaticLongMethodV/callLongMethodV trả 8000000L. license OK lại.
  - **2 collect-thread:** `0x4f980` chạy INLINE OK (x0=0x40b82070,x1=0x40b82150 valid, không get_seed); `0x4dda0` = thread crash-với-scheduler.
  - 🎯 **MSB_CALLTHREAD gọi `0x4dda0(0)` TRỰC TIẾP → ret=0xffffffff (CHẠY xong, KHÔNG crash/hang!)** — bypass scheduler VIABLE.
    Chỉ sai arg0 (THREAD_CTX=0 vì MS.b 0x2000001/0x3000001 không fire). Scheduler intended arg0=`0xfffe0080` (SVC-trampoline callback).
  - **Tension provisioning:** MSB_THREADS → get_seed chạy nhưng scheduler crash (0x4dda0→0x81, chỉ khi props mở full-path); KHÔNG threads →
    không crash nhưng GET_SEED=0 (thread inline 0x4f980 không làm get_seed) → pskVersion="none". Report 296/320B, #18/#19 absent.
  - **#18 device-stable** ⇒ PSK từ CACHE (.msp/.mss) chứ không phải get_seed (seed đổi mỗi session, #18 không). get_seed có thể chỉ cho #24.
  - **Còn lại (multi-piece):** (a) đúng arg0 cho 0x4dda0-direct-call (capture 0xfffe0080 trampoline) → provision không-scheduler; HOẶC
    (b) load PSK từ .msp/.mss cache (main-thread) → cần biết chỗ pskHash đọc PSK. Grind converging nhưng nhiều piece.

- 2026-08-18 (b: cache-PSK — unidbg GIẢI MÃ .msp_589c OK [no-TEE reconfirm], nhưng PSK-marker ở nơi khác):
  - Cache ops unidbg (props, no-crash): `.msp_589c`(377B seed/state) READ-only (378B, không ghi); `.msp_092f`(sdi_v2) R/W nhiều;
    `.msf3_*`(semithc/ecneuq/sdi/msmodel) R/W. **`.mss_9b8e`(630B) + `.msf3_e1beed`(132B) KHÔNG được đọc** trong unidbg.
  - 🎯 **CORRUPT TEST [decisive]:** flip 300B giữa `.msp_589c` → **0 report** (metasec fail). ⇒ **unidbg GIẢI MÃ .msp_589c THÀNH CÔNG**
    (software-crypto chạy được, NO-TEE tái xác nhận lần 2). Nhưng clean-run: .msp_589c decrypt OK mà **pskVersion vẫn "none"**
    ⇒ **PSK-provisioned marker KHÔNG trong .msp_589c** (nó là seed/state base). PSK đến từ: collect-thread derivation HOẶC .mss_9b8e (unidbg chưa đọc).
  - **Lead (b) tiếp:** vì sao unidbg KHÔNG đọc `.mss_9b8e`(630B)/`.msf3_e1beed`(132B)? Nếu phone đọc chúng (chứa PSK) mà unidbg bỏ qua →
    đó là gap. Điều kiện đọc .mss_9b8e không đạt trong unidbg (thiếu state/flag từ collect-thread).
  - **Tổng cảnh [honest]:** mọi layer thượng nguồn GIẢI (license/props/getStartElapsed/decrypt-works). Còn lại = **PSK-provisioning**
    (collect-thread derivation) — cùng gốc với thread-crash. NO-TEE confirmed 2x ⇒ offline khả thi nguyên lý, nhưng provisioning là multi-piece grind.

- 2026-08-18 (grind tiếp: direct-call arg — xác nhận cần thread-context+TLS, direct-call KHÔNG đủ):
  - `0x4dda0(arg0=0)` → ret error (null-check sớm, không provision). `0x4dda0(arg0=0xfffe0080)` → crash FETCH_UNMAPPED
    (trampoline đó chỉ tồn tại khi scheduler tạo; không có MSB_THREADS thì nó chưa mapped). Cả hai KHÔNG provision.
  - ⇒ **0x4dda0 cần context+TLS thật** (như 0x4f980 chạy inline có x0=0x40b82070 valid) — mà setup này chỉ scheduler dựng.
    Direct-call bypass CHẠY được về cơ chế nhưng **thiếu thread-context proper** → không đủ để provision.
  - **Xác nhận [honest]:** provisioning PSK **cần thread-machinery unidbg hoạt động** (context/TLS/trampoline). Đây = **patch unidbg
    thread-scheduler (multi-day)**, không phải quick-iterate. Grind nhanh đã cạn (license/props/getStartElapsed/direct-call đều thử).
  - **TRẦN thực tế đường unidbg thuần:** mọi layer khác GIẢI (report 486B genuine #16/#24/#32, NO-TEE, decrypt-works). #18/#19 chặn bởi
    unidbg-0.9.8 không chạy được collect-thread provisioning. 2 lối thoát: (1) fork/patch unidbg thread-dispatch (multi-day, deep);
    (2) 1-phone-extract PSK-đã-decrypt (hook phone lúc decrypt xong, inject) — cần phone 1 lần nhưng né hẳn thread.

- 2026-08-18 (B: bắt đầu fork unidbg scheduler — pin bug, nhưng completion = multi-day proper-dev):
  - `Function64.run`: `backend.reg_write(LR, until); emulate(address, until)`. Crash PC=LR=0x81 ⇒ thread-task `until`/context = 0x81 (sai).
  - `BaseTask.continueRun`: `context_restore(context); pc=reg_read(PC); emulate(pc, until)` — PC restore về 0x81 = **context corrupted/uninit**
    (context_alloc/save/restore của cooperative-scheduler). + STATUS cũ: "MarshmallowThread stack-write fail" = thread-stack chưa map đúng.
  - metasec KHÔNG dùng pthread_create (hook ko fire) → thread tạo qua clone/cơ chế khác → unidbg tạo Function64 với until/stack sai.
  - 🎯 **THỰC TẾ [honest]:** fix = patch unidbg cooperative-scheduler (context save/restore + thread-stack alloc + until cho thread-entry).
    Cần **checkout unidbg source + build + step-debugger** để làm đúng — decompiled-bytecode + WebFetch-summary trong env này KHÔNG đủ.
    Đây là **project riêng multi-day-to-week**, không phải hoàn tất trong 1 phiên.
  - **Đã pin chính xác cho lần làm proper:** classes = `Function64`/`MainTask`/`BaseTask`/`ThreadTask`/`MarshmallowThread`/`UniThreadDispatcher`;
    triệu chứng = thread-task until=0x81 + context-restore→0x81 + thread-stack-write-fail; shadow-class-override khả thi (như NetLinkSocket).

- 2026-08-18 (#3 nâng unidbg version — DEAD END [tested]):
  - Maven Central: unidbg-android CHỈ có tới **0.9.9** (không 0.9.10+). Nâng 0.9.8→0.9.9: **CÙNG crash `0x81 @ Function64 0x4dda0 args=[0xfffe0080,null]`**
    (scheduler bug KHÔNG được fix ở 0.9.9) + unicorn 1.0.15 native **crash JVM** (đúng note pom). ⇒ Reverted về 0.9.8.
  - ⇒ Không có "free fix" qua version. Còn lại: (1) fork unidbg-scheduler proper-dev; (2) 1-phone-extract; emulator khác (Qiling); HOẶC server-test gate.

- 2026-08-18 (FORK unidbg — ROOT-CAUSED crash 0x81 = signal/ucontext, KHÔNG phải scheduler-context-bug):
  - Instrument shadow Function64 + BaseTask (src/main/java/com/github/unidbg/... override, MSB_SCHEDLOG). Phát hiện:
  - **`0x4dda0` = JNI_OnLoad** (không phải collect-thread!). Creator: DalvikModule.callJNI_OnLoad→eFunc(0x4dda0,[JavaVM=0xfffe0080,null]). until chuẩn.
  - JNI_OnLoad chạy → `svc #0` @0x16c190 **syscall x8=131 = tgkill** (tự gửi signal). unidbg preempt: SAVE ctx pc=0x16c194.
    **Context SAVE/RESTORE HOÀN HẢO** (pc/lr/x0/sp khớp hệt) → KHÔNG phải context-corrupt bug.
  - Sau resume → wrapper ret → caller `0x16dff8 ret` nạp x30 từ stack = **0x81** → crash. Tức signal-handling làm hỏng luồng/stack.
  - 🎯 **ROOT [confirmed]:** `linux/signal/SignalTask.runHandler` truyền **ucontext = malloc(0x1000, TRUE)=ZEROED** cho handler (X2),
    chạy handler qua emulate, **KHÔNG populate CPU-state thật + KHÔNG sigreturn** (resume caller từ ctx riêng, bỏ qua ucontext).
    metasec dùng **tgkill+signal-handler+ucontext để control-flow (anti-analysis)** → ucontext rỗng + no-sigreturn → luồng metasec vỡ → 0x81.
  - **FIX (substantial unidbg enhancement):** shadow SignalTask.runHandler → (1) populate ucontext với regs thật (ARM64 mcontext offsets:
    sigcontext @uctx+0xB0, regs[31]@+8, sp@+0x108, pc@+0x110); (2) sigreturn: sau handler đọc ucontext.pc/regs, apply vào task resume.
  - Tools: shadow `src/main/java/com/github/unidbg/thread/{Function64,BaseTask}.java` (SLOG). Sources 0.9.8 tại /tmp/uapi,/tmp/uand.

- 2026-08-18 (FORK tiếp — handler signum-64 = flag-set, KHÔNG dùng ucontext; partial-fix; non-deterministic):
  - Disasm handler @metasec+0x128464 (signum=64/SIGRTMAX): gọi 0x17a17c/0x17a308, set global `[0x1f31c0]=0x4bd`, ret.
    **KHÔNG đọc/sửa ucontext (X2)** → signal = **async-notification/thread-sync flag**, không phải ucontext-control-flow.
  - Shadow SignalTask populate-ucontext (src/main/java/com/github/unidbg/linux/signal/SignalTask.java) → run ĐÔI KHI xong (exit=0,
    `===END===`), đôi khi hang (124) — **non-deterministic** (race trong cooperative-scheduler). Crash 0x81 vẫn 1 lần (non-fatal ở run xong).
  - `#18/#19` VẪN absent, pskVersion="none": get_seed/provisioning chưa hoàn tất (GET_SEED=0 ở run hang — thread setup bị 0x81 làm gián đoạn).
  - 🎯 **Trạng thái fork [honest]:** đã root-cause CHÍNH XÁC (signal-64/tgkill + unidbg signal-delivery) + partial-fix (ucontext populate).
    Nhưng còn: (a) crash 0x81 sau signal (stack/return corrupt — chưa rõ điểm chính xác); (b) non-determinism scheduler; (c) provisioning
    chưa xong. Đây ĐÚNG là **multi-day deep-dev** như đã cảnh báo — root-caused nhưng chưa hoàn tất.
  - Shadow classes (gated MSB_SCHEDLOG, off mặc định): Function64, BaseTask, linux/signal/SignalTask. Sources 0.9.8: /tmp/uapi, /tmp/uand.

- 2026-08-18 (A: SIGTRACE — 0x81 là RACE non-deterministic, KHÔNG phải điểm crash cố định):
  - MSB_SIGTRACE (CodeHook log mọi PC từ resume 0x16c194): run exit=0 → execution **chạy tiếp 400+ instr bình thường**
    (meta+0x5ae2c→0x5c124, SP tiến triển) — **KHÔNG crash sau resume**. Nhưng run khác: 0x81=1 (crash), reports=0.
  - 🎯 **0x81 = RACE:** cùng code-path, đôi khi crash đôi khi không — do **thứ tự signal-delivery + thread-scheduling** trong
    cooperative-scheduler thay đổi mỗi run (non-deterministic). ucontext-populate fix giúp 1 số run qua, nhưng race vẫn còn.
  - Provisioning (GET_SEED, #18/#19) vẫn chưa hoàn tất kể cả run exit=0 (thread/get_seed ordering bị race ảnh hưởng).
  - 🎯 **FORK [honest, chốt]:** đã root-cause + partial-fix. Blocker cuối = **fix RACE trong cooperative-scheduler của unidbg**
    (signal+thread ordering) + hoàn tất provisioning. Đây = **sustained multi-day-to-week deep-dev với step-debugger** — vượt khả năng
    grind-nhanh trong env này. Đã đẩy fork xa nhất có thể không cần debugger tương tác.
  - Shadow permanent: SignalTask ucontext-populate (cải thiện, giữ). Function64/BaseTask/SIGTRACE gated MSB_SCHEDLOG/SIGTRACE (off).

- 2026-08-18 (🎯 RACE FIXED via MSB_THREADS_DEFER + tách bạch reliability vs #18/#19):
  - **FIX race [WIN]:** dời `enableThreadDispatcher(true)` xuống SAU JNI_OnLoad (env `MSB_THREADS_DEFER`) → JNI_OnLoad chạy dispatcher-off
    (tgkill trả 0, no-yield, no-race) → **JNI_OK=1, 0x81=0 (KHÔNG crash), END=1, get_seed×2, deterministic**. Race biến mất hoàn toàn.
  - Threads giờ chạy đủ: DYN_TASK + GET_SEED×2 + call#3(436→76) + (thread-time dài) **`.mss_9b8e` ĐƯỢC ĐỌC** (4×, trước không). Report
    có thêm #27, #24=132B. Nhưng **pskVersion VẪN "none", #18/#19 VẪN absent, report 486B**.
  - 🎯 **TÁCH BẠCH [quan trọng]:** report luôn 486B dù race-crash hay không ⇒ **crash race = vấn đề RELIABILITY riêng** (unidbg-scheduler),
    **KHÔNG phải nguyên nhân #18/#19**. `#18/#19` bị chặn bởi **PSK/KMS provisioning** (device-bound) — vấn đề TÁCH BIỆT, không do thread/race.
  - ⇒ Fork/race-fix hoàn tất phần reliability (đóng góp thật cho unidbg-emulation), nhưng #18/#19 vẫn = **PSK device-bound**: threads đọc
    .mss_9b8e/get_seed nhưng pskVersion không flip → KMS/PSK cần state provision-once trên real-device (không tái tạo qua network unidbg).
  - **Trần chốt [honest]:** unidbg giờ CHẠY TIN CẬY end-to-end (race fixed), report 486B genuine ổn định. #18/#19 = PSK device-bound,
    quay lại đúng kết luận NO-TEE-nhưng-provision-device-bound. Đường tới #18/#19: 1-phone-extract PSK (đã xác nhận là hướng còn lại).
  - New env: `MSB_THREADS_DEFER` (fix race). Shadow SignalTask ucontext-populate (giữ). Function64/BaseTask/SIGTRACE gated.

- 2026-08-18 (VERIFY nguyên nhân pskVersion="none" — REFUTE network-fail + cache, CONFIRM trust-gated):
  - Network (MSB_NET, full-URL): **3 endpoint đều 200 OK**: `ms/dyn/task`(44), `ms/get_seed`(189×2 → #24 OK), `sdi/get_token`(76 → #16 OK).
    Response decrypt được. **KHÔNG endpoint KMS/psk riêng nào được gọi.** ⇒ network provisioning THÀNH CÔNG, không phải nguyên nhân.
  - Corrupt-test: `.mss_9b8e` corrupt → **dung thứ** (END=1, report=1, không đổi) = KHÔNG critical; `.msp_589c` corrupt → **0 report** = critical/decrypt-work.
    ⇒ PSK KHÔNG load-từ-cache.
  - 🎯 **NGUYÊN NHÂN [refined, evidence-based]:** pskVersion="0"(KMS) **không do provisioning-chuẩn** (chạy đủ+thành công) mà **trust/config-gated**:
    metasec TỰ quyết định KHÔNG bật KMS (không thử endpoint KMS nào) vì device không đạt "genuine/trusted", hoặc dyn/task-config trả "no-KMS".
    Phone bật được vì genuine+registered-once; state KMS device+trust-bound, unidbg (dù khớp DID) không được nhận genuine → "none".
    = **anti-tamper theo thiết kế**: PSK/KMS = gốc-tin-cậy chỉ cấp thiết bị thật đã-xác-thực.
  - **CHỐT:** #18/#19 chỉ có qua PSK-genuine từ thiết bị thật → **1-phone-extract** (trích KMS/PSK-state provision từ phone, inject) là đường duy nhất.

- 2026-08-19 (NGUYÊN NHÂN definitive — phone gọi CÙNG 3 endpoint → cause = circular/trust, không phải thiếu call):
  - Hook phone MS.b(0x30001): phone gọi **y hệt** `ms/dyn/task`, `ms/get_seed`, `sdi/get_token` (+ config JSON app_version="v05.02.07-ov-android").
    ⇒ **unidbg KHÔNG thiếu endpoint nào.** Loại bỏ "missing-call" cause.
  - 🎯 **NGUYÊN NHÂN GỐC [proven bằng loại trừ]:** VÒNG LẶP chicken-egg — server cấp KMS/PSK (pskVersion="0") chỉ khi request
    get_token/get_seed ký GENUINE (có #18/#19). unidbg ký degraded (thiếu #18/#19 vì chưa có PSK) → server không nhận genuine →
    không cấp KMS → pskVersion="none" → không sinh được #18/#19. Thiết bị thật thoát vòng vì bootstrap-genuine-1-lần lúc register.
  - **Lead phụ (chưa test):** unidbg URL `sdk_ver=v05.02.07-alpha.6-ov-android` (từ license mus4573) vs phone config `v05.02.07-ov-android`.
    "alpha.6" có thể là thêm signal non-production khiến server từ chối KMS. Nếu bỏ được alpha.6 mà license valid → đáng thử.
  - **CHỐT:** #18/#19 bất khả trong unidbg thuần (vòng lặp + trust). Đường duy nhất = 1-phone-extract PSK genuine.

- 2026-08-19 (SOLUTION B test — fresh bootstrap: server CHẤP NHẬN unidbg, nhưng unidbg chưa hoàn tất luồng):
  - Chạy fresh (MSB_DEVSTATE_DIR=empty) → metasec làm **luồng bootstrap đầy đủ**, gọi thêm endpoint MỚI (chỉ có khi fresh):
    `common_config/v1/info`, `ms/dyn/report` + dyn/task/get_token/get_seed. **dyn/task resp = 42958 bytes** (full config, vs 44B cached).
  - 🎯 **QUAN TRỌNG:** mọi call 200 OK, server trả FULL CONFIG cho device-mới ⇒ **server ĐỐI XỬ unidbg-fresh như thiết bị mới hợp lệ**,
    rào KHÔNG phải server-side. Rào = **unidbg-side chưa hoàn tất fresh-flow**: "SDK not init" quay lại (cache-state chưa dựng) +
    hang tại SVC-trampoline `0xfffe0784` (svc #0x16f = callback, cùng lớp signal/thread issue như tgkill).
  - **Đánh giá B [cập nhật, tăng lên ~50-60%]:** hướng đúng, server không chặn. Cần: (1) hoàn tất fresh-bootstrap trong unidbg
    (fix SDK-not-init-fresh + signal-hang mới), (2) xử lý config 42958B. = thêm unidbg-engineering (cùng lớp đã làm được với DEFER/ucontext).
  - **So sánh:** B (fresh-bootstrap) giờ khả thi hơn A (extract PSK từ VM-memory, khó localize). B né được việc trích PSK.

- 2026-08-19 (B hoàn tất fresh-flow — MSB_DEVSTATE_CREATE fix hang, NHƯNG KMS vẫn không provision; hệ quả cho A):
  - `MSB_DEVSTATE_CREATE` (IOResolver cho tạo file mới khi O_CREAT) → fresh-flow **HOÀN TẤT tin cậy** (exit=0, END=1, SDK-not-init 2 (hết loop),
    persist 3 file: .msf3_b99e/.msp_092f/.msp_589c). Fix được hang svc#0x16f (do loop SDK-not-init vì không persist được state).
  - Multi-launch (2,3): END=1 nhưng **files vẫn 3, KHÔNG tạo .mss_9b8e/KMS-cache**, pskVersion vẫn "none". ⇒ KMS KHÔNG provision kể cả fresh+repeat.
  - 🎯 **HỆ QUẢ CHO A [quan trọng]:** đã feed _ds_cur (CÓ .mss_9b8e = KMS-cache genuine của phone) mà pskVersion vẫn "none". ⇒ metasec
    **RE-EVALUATE KMS lúc runtime, BỎ QUA cached-KMS** → **Solution A (inject PSK-cache) CŨNG KHÔNG chạy** vì metasec tự đánh giá lại + trượt.
  - **CHỐT A/B/C:** B (fresh) — server chấp nhận nhưng metasec/server **withhold KMS** cho device không-genuine. A (inject cache) — metasec bỏ qua cached-KMS.
    ⇒ Cả A lẫn B đều **không phá được** vì KMS-enablement = **runtime trust-evaluation**, không do cache/bootstrap. Chỉ còn: **force gate (patch pskVersion=0)
    + cấp PSK cho VM** (crux, VM-buried) HOẶC device-oracle (C-ish, chạy metasec trên máy thật).
  - **WIN phụ B:** unidbg giờ chạy được CẢ fresh-bootstrap-flow (MSB_DEVSTATE_CREATE) — hoàn thiện emulation.

- 2026-08-19 (🎯 BREAKTHROUGH [user redirect đúng] — device-signal mismatch = nguyên nhân LOCAL, KHÔNG phải infeasible):
  - Re-investigate theo methodology user (Track B signal-tracing). Hook MS.b phone → bắt **giá trị THẬT phone trả cho collect-callback**:
    `0x1000001`=**/data/app/…/base.apk (APK PATH!)**, 0x1000009=Asia/Ho_Chi_Minh,7(tz), 0x100001a=en_(locale), 0x100001c=IPs,
    0x1000017=8, 0x1000005=560, 0x1000010=2024507030, 0x1000011=45.7.3, 0x100001d/34=false. **unidbg trả NULL gần hết.**
  - 🎯 **`0x1000001`=APK-path = mấu chốt:** metasec đọc APK verify **chữ ký app (SHA1 signing-cert) = anti-tamper**. unidbg null →
    không verify được → app coi TAMPERED/non-genuine → **withhold KMS** → pskVersion="none" → không #18/#19. ĐÚNG "App Signature" suspect-list.
  - **SỬA KẾT LUẬN CŨ:** "infeasible/circular/needs-genuine-device" là SAI (đã tunnel). Nguyên nhân THẬT = **LOCAL device-signal mock sai**
    (đặc biệt APK-signature). FIXABLE: cấp signal phone-values + APK thật (có cur_base.apk 560MB) cho metasec verify → genuine → KMS.
  - Có: `frida/out/cur_base.apk` (APK thật, chữ ký official). Callback-handler Harness ~line 738. Đang implement inject signals + APK-path + IOResolver-cho-apk.

- 2026-08-19 (Track B exhaustive — signal-theory REFUTED bằng test; thu hẹp gate):
  - Capture TOÀN BỘ phone signals+keva. Cấp CHÍNH XÁC (MSB_SIGNALS + MSB_SIGNALS_EXACT: path/tz/locale/IP/version + null cho cmd phone-None).
    keva `sdi`(32B) KHỚP; semithc/ecneuq session-variable. → **pskVersion VẪN "none", #18 absent.** ⇒ **collect-signals KHÔNG phải KMS-gate.**
  - APK-path 0x1000001: metasec nhận đúng path nhưng **KHÔNG đọc APK** (collect-only, không local-sig-verify). Loại "APK-signature-local".
  - 🎯 **TỔNG KẾT 2 lý thuyết [đều test]:** (1) "infeasible/circular" (tôi) — chưa chứng minh dứt; (2) "local device-signal" (user redirect) —
    **REFUTED** (cấp exact signal không flip). Cache/fresh-bootstrap cũng không flip. ⇒ KMS-gate KHÔNG phải: collect-signal, cache, fresh, APK.
  - **Còn lại 2 ứng viên:** (A) **SETTINGS-config** (ms_settings_android blob / dyn-task-config bật KMS) — unidbg có thể không apply/decrypt được;
    (B) **request-signing/get_token-response** (KMS đến TỪ server-response, cần request genuine — circular). Cả hai sâu hơn signal.

---
## [2026-08-19] TEST DỨT ĐIỂM: gate = "SDK not init", KHÔNG phải transport/seed/MediaDrm

Chạy combo genuine đầy đủ (FULLINIT+THREADS+NET+KV+SIGNALS+PROPS, real DID/IID, **MSB_DUID=735a4c…444500** = Widevine deviceUniqueId THẬT của phone):
- ✅ get_seed FIRE, server 200 + dyn_seed 189B (x2)
- ✅ MediaDrm(Widevine) gọi, `getPropertyByteArray(deviceUniqueId)` nhận **MSB_DUID thật 32B**
- ✅ sdi/get_token FIRE, server 200
- ❌ report VẪN 448B: **#18 ABSENT, #19 ABSENT, #20="none", #32 ABSENT** (#16 25B + #24 132B present)
- ❌ SIGN vẫn `E/METASEC: Fatal: SDK not init, crashing` (2×)

**KẾT LUẬN (tested):** #18/#19/#32 + #20 pskVersion bị gate BỞI cờ **"SDK-init-complete"** (sign check `cmp w8,#0x40c`), KHÔNG phải:
- ❌ transport/TLS (curl_cffi replay get_seed → 200, mọi TLS profile giống nhau)
- ❌ get_seed/dyn_seed (đã pull 200/189B, note 31)
- ❌ MediaDrm deviceUniqueId (feed DUID thật → #18/#19 vẫn absent; làm mềm note 30 "MediaDrm-gate")
- ❌ device-signal (session trước refute)

Init-flag `[base+0x1f0cf0]` sau FULLINIT 0x1000003 = 0x0 (nhưng đó là function-pointer, không phải cờ — xem memory). Cờ thật (giá trị kỳ vọng 0x40c) nằm chỗ khác, VM-buried. Collect chạy xong (seed/DUID/token 200) NHƯNG cờ vẫn không set ⇒ init-completion native có check phụ fail trong unidbg (nghi: cooperative-scheduler timing — collect chưa drain xong khi sign check; hoặc 1 init-cmd còn thiếu).
**Repro log:** scratchpad/genuine_run_fulllog.txt

## [2026-08-19b] Định vị gate xuống 1 địa chỉ + phone-validate; watchpoint-init bị anti-frida chặn

**Dynamic (MSB_WATCH trong unidbg):** state = `*(*(base+0x1e3690))` = `*(base+0x1ef888)`. Watchpoint bắt **0 write** lên 0x1ef888 cả run ⇒ writer KHÔNG BAO GIỜ chạy. Writer = block base+0x4ef20 (`str x0,[P]`@0x4efc4) = SDK-context lazy-singleton-init; CodeHook chứng minh block này **không bao giờ được VÀO** (caller gián tiếp trong hàm OLLVM-flattened không fire). Xref tĩnh tới 0x4ef20 trống (BL/adrp/reloc) → basic-block trong flattened fn tới qua `br x1`.

**Phone .so KHÁC unidbg:** phone `/data/app/...musically.../lib/arm64/libmetasec_ov.so` = 2032384B md5 02f4757… (= libs_trill build); unidbg vendor = 1982816B md5 bd2b527… (= libs build). Offset KHÔNG transfer. Tái phân tích phone .so: string@0x17d5a0, gate GP=0x1ef698 (22 site, 21 dẫn string), P=*(GP)=**0x1fbb00** = state qword phone.

**Phone live (attach-warm PID):** state=*P=**0x2f42** (≠0, init xong). Dump object @base+0x1fbb00: P+0=0x2f42, **P+8=linker64+0x2dff8 (ptr), P+0x18/0x30/0x40/0x50 = heap ptr** ⇒ object nhúng con trỏ heap/linker → **transplant thô BẤT KHẢ** (khớp note 23 G1 "deref field crash").

**Watchpoint-init BỊ CHẶN:** state ghi 1-lần lúc init; warm app đã =0x2f42 (không bắt được lúc ghi). Spawn tươi để bắt 0→nonzero → **anti-frida KILL app ngay sau khi arm HW watchpoint/exception-handler** (state0=0x0 lúc load rồi im lặng, app chết). MAM cũng 0 hit. ⇒ không lấy được caller-backtrace qua frida spawn.

**Đường còn lại (đề xuất):** MINIMAL-FAKE trong unidbg (không đụng phone/anti-frida): trace hàm sign (base+0x9af80) sau init-check `cbnz` đọc field nào của object → synth object tối thiểu tại base+0x1ef888 + set state≠0 → xem #18/#19 hiện. Hoặc: nạp ĐÚNG build phone (2032384) vào unidbg cho khớp layout. Note 23 G2 caveat: ép init trước đó không tạo trust.

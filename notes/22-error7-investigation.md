# 22 — ĐIỀU TRA ROOT CAUSE: API Login Error 7 (báo cáo liên tục cập nhật)

> 🔁 **SUPERSEDED-BY note 24 (audit 2026-09-04):** kết luận 'ROOT CAUSE = root FAIL hardware/Play-Integrity attestation, fix = PIF' bị đảo ngược hoàn toàn bởi chuỗi W13-W17 của note 24: root được minh oan (login+register pass), identity-rotate bị bác, cuối cùng = **VELOCITY (W16) + bản chất fingerprint-forge offline (W17)**. Không có hardware-attestation/TEE nào tham gia. Control-tests A1 (ec7 = thuộc tính device_id) và A3 (s không đo trust) vẫn đứng.


> Mục tiêu: xác định **nguyên nhân gốc THẬT** của `error_code 7` khi login, kèm bằng chứng tái lập được.
> Nguyên tắc: KHÔNG đoán. Mỗi kết luận có Giả thuyết/Bằng chứng/Kiểm chứng/Kết quả/Độ tin cậy.
> Cái gì chưa chứng minh → ghi rõ UNVERIFIED. Nối [[21-mssdk-getseed-attestation]], [[20-device-id-mechanics]].

---

## KẾT LUẬN ĐIỀU HÀNH (cập nhật 2026-07-21, sau E1 — ĐÃ XÁC NHẬN)

**ROOT CAUSE (CONFIRMED, độ tin cậy CAO):** `error 7` = `device_id` UNTRUSTED. device_id untrusted vì
**phone FAIL hardware attestation** — bị ROOT (Magisk) **mà KHÔNG có attestation module hoạt động**
(safetynet-fix/PlayIntegrityFix). **Chữ ký/loại app (mod hay official) KHÔNG liên quan.**

Chuỗi bằng chứng (mỗi mắt xích đã kiểm chứng):
1. error 7 = thuộc tính `device_id` (control test: 7632→1108 vs 766484→ec7, cùng account/lúc/signer). **CAO**
2. Loại HẾT layer khác: signature (byte-verified + oracle genuine 688 vẫn ec7), header/query/body/version/msToken (byte-diff khớp), account/IP (control), dsign-s (s=0 vẫn trusted). **CAO**
3. **E1 loại app-mod:** app OFFICIAL (sig `194326e8...` verified genuine) register sạch → **VẪN ec7** = y hệt app mod. device_id dedup theo fingerprint device-wide (cùng 766484 bất kể app). **CAO**
4. Còn lại DUY NHẤT: **attestation**. Khớp chính xác quy tắc PROVEN `factory/docs/03-CONG-THUC.md`:
   *"Root KHÔNG safetynet-fix → FAIL attestation → error 7 untrusted"* + cấu hình máy khớp (root, modules rỗng). **CAO**

**FIX:** cài attestation module hoạt động (PlayIntegrityFix) để phone PASS attestation → device mới trusted.
**Rào cản trên đúng máy này:** Magisk 24.3 (quá cũ cho PIF) + base Android 8/patch 2020 (xem Phần D).

---

## PHẦN A — CONFIRMED (đã chứng minh, độ tin cậy cao)

### A1. error 7 nằm ở `device_id`, KHÔNG phải account/IP/request
- **Giả thuyết:** error 7 do thuộc tính của device_id, không phải account bị khóa/rate-limit hay IP.
- **Bằng chứng + Kiểm chứng (control test, 2026-07-21, cùng account cùng lúc cùng signer UNIDBG):**
  | device | account | kết quả |
  |---|---|---|
  | 7632162877655729682 (real, aged) | user28122 | **ec 1108** (qua ec7) |
  | 7664840433364993556 (rotated, mới) | user28122 | **ec 7** |
  Chạy back-to-back, chỉ khác `device_id`. 7632 → 1108 (không phải 7) ⇒ **account KHÔNG rate-limit**;
  cùng IP máy PC ⇒ **IP không phải biến**.
- **Kết quả:** biến duy nhất tạo ra 7 = `device_id`.
- **Độ tin cậy: CAO.**

### A2. Loại signature/header/body/version/msToken (từ re/STATUS, byte-verified)
- **Bằng chứng (re/STATUS 5b, v2):** request pure-API 45.0.3 **byte-diff KHỚP genuine 45.0.3** (0 header-value-diff,
  0 body-diff). x-argus **GENUINE** (metasec oracle phone thật, 688 ký tự) + forge device → **VẪN ec7**.
  x-argus UNIDBG (offline, 324) + device 7632 thật → **2135/1108** (qua). msToken/warmup đủ → vẫn phụ thuộc device.
- **Kết quả:** signature-quality, header, query, body, version, msToken **ĐỀU KHÔNG phải** nguyên nhân (loại).
- **Độ tin cậy: CAO** (byte-verified + oracle test).

### A3. dsign `s` KHÔNG phải thước đo trust
- **Bằng chứng:** device 7632 (trusted) dsign trả **s=0** vẫn login qua (1108). Forge s=1 vẫn ec7 (re/STATUS).
  Session này: cả 7632 và 766484 đều `dsign s=0`.
- **Kết quả:** `s` không tương quan trust. Loại.
- **Độ tin cậy: CAO.**

### A4. Phân biệt device trusted vs untrusted (data thực)
- | device | nguồn | login |
  |---|---|---|
  | forge (pure-API register) | re/src/device.mjs + unidbg | **ec7** |
  | 7664840433364993556 | rotated + hidden-root + **app MOD**, no-attestation | **ec7** |
  | minted (phone + safetynet-fix, fresh) | factory/regbox | **SUCCESS** (re/STATUS 07-13) |
  | 7632162877655729682 | app THẬT, aged, có history | **1108/2135** (trusted) |
- **Kết quả:** trusted ⇔ (đăng ký trên phone PASS attestation). Untrusted ⇔ forge HOẶC root-không-attestation.
- **Độ tin cậy: CAO.**

---

## PHẦN B — GIẢ THUYẾT DẪN ĐẦU (mạnh, nhưng CHƯA isolate)

### B1. Root cause = phone FAIL hardware attestation (thiếu safetynet-fix/PIF)
- **Giả thuyết:** device_id mới untrusted vì phone root KHÔNG có attestation module → server thấy device
  không pass Play Integrity/SafetyNet → mint device_id ở mức untrusted → error 7.
- **Bằng chứng:**
  1. **factory/docs/03-CONG-THUC.md (tài liệu PROVEN nội bộ, 2026-06-22)** ghi bảng nhân-quả:
     *"Root + safetynet-fix → trusted; **Root KHÔNG safetynet-fix → FAIL attestation → error 7 untrusted**."*
     (proven: device rotate 7654139800336844309 → check_email SUCCESS 1011).
  2. **Cấu hình máy ce031603 khớp CHÍNH XÁC dòng "Root không safetynet-fix":**
     `magisk 24.3` + `/data/adb/modules` **RỖNG** (không safetynet-fix/PIF) — verify session này.
  3. Device trusted (7632, minted cũ) đều đăng ký khi phone CÓ attestation-pass (app thật + safetynet-fix era).
- **Kiểm chứng ĐÃ làm:** rotate fresh fingerprint + ẩn root (Zygisk DenyList — verify mount sạch) + register sạch
  (frida OFF verify bằng port 27042 + ps-exact) → device mới `766484` → **ec7**. Khớp tiên đoán của recipe.
- **Kết quả:** khớp 100% quy tắc nhân-quả tài liệu proven.
- **Độ tin cậy: CAO cho cả "attestation là nguyên nhân" VÀ "là nguyên nhân DUY NHẤT"** — sau khi **E1 (Phần C1)
  đã loại app-mod** (biến đồng hành duy nhất), attestation là biến còn lại duy nhất chưa loại và khớp recipe proven.

---

## PHẦN C — HYPOTHESIS ĐÃ LOẠI bằng thí nghiệm E1

### C1. App MOD (chữ ký tampered) → ĐÃ LOẠI (không phải nguyên nhân)
- **Giả thuyết:** metasec chấm chữ ký APK; app mod (chữ ký khác official) → tampered → untrusted.
- **Kiểm chứng E1 (2026-07-21):**
  1. Gỡ app mod, cài **app OFFICIAL 45.7.3** (apkpure). **Verify chữ ký:** cert DER MD5 = `194326e82c84a639a52e5c023116f12a` = **KHỚP sig genuine** trong `device.mjs` ⇒ đúng app official thật.
  2. Gỡ cert MITM (system+user store) + denylist active + frida OFF (port 27042 closed) + register qua forward-proxy sạch (mobile/proxy.mjs, KHÔNG decrypt).
  3. App official register → **device_id = `7664840433364993556` (TRÙNG y hệt app mod!)**, install_id mới. ⇒ device_id **dedup theo fingerprint device-wide (GSF/GAID/serial dùng chung), KHÔNG theo chữ ký app.**
  4. Đo `t_trusted.mjs` (device 766484, đã register qua app official sạch) → **user/login ec=7** (y hệt app mod).
- **Kết quả:** app official (sig verified) + register sạch → **VẪN ec7**. Đổi mod→official **không thay đổi gì**.
- **Kết luận: app-mod KHÔNG phải nguyên nhân.** device_id là 1 (dedup fingerprint) bất kể app; trust nằm ở device, không ở app.
- **Độ tin cậy: CAO.** (Ghi chú confound dư: 766484 có lịch sử first-register bởi app mod — nhưng vì device_id dedup theo fingerprint device-wide, server coi là 1 device bất kể app, nên confound này không hợp lý. Muốn 100% tuyệt đối: rotate GSF/GAID/serial mới → device_id chưa-từng-chạm-app-mod, register official-only — nhưng chuỗi bằng chứng hiện tại đã đủ mạnh.)

---

## PHẦN D — RÀO CẢN KỸ THUẬT (đã verify, ảnh hưởng phương án FIX)
- Magisk **24.3 (2022)** — quá cũ cho PIF hiện đại (cần 26.4+). Zygisk maps zygote = 0 (có thể chưa inject đầy đủ).
- Base fingerprint **Android 8.0.0**, security patch **2020-07-05** → Play Integrity DEVICE verdict dễ FAIL.
- **SafetyNet API bị Google tắt 1/2025** → safetynet-fix cũ chết; chỉ PIF dùng được (mà PIF cần Magisk mới).
- ⇒ FIX attestation trên đúng máy này = việc lớn/rủi ro (update Magisk → reflash boot → nguy cơ bootloop).

---

## PHẦN E — REMAINING UNKNOWNS (sau E1)
1. ✅ ~~E1: app-mod~~ → ĐÃ LOẠI (Phần C1). Root cause = attestation, CONFIRMED.
2. ✅ **metasec dùng Google Play Integrity — ĐÃ XÁC ĐỊNH (RE tĩnh + runtime, 2026-07-21):**
   - App có Play Integrity API: `play/core/integrity` + `requestIntegrityToken` trong 5 DEX (classes 2/17/22/31/33) [grep -a].
   - libmetasec_ov.so có field `safetyNet` (`el_distribution safetyNet msmodel_ca`).
   - Runtime: GMS `potokens.IntegrityTokenRefreshTaskService` chạy khi dùng app (PI infra active).
   - **Nhưng đọc LOCAL, spoof được:** device_register body plaintext KHÔNG có field integrity; mitm captures chỉ Firebase JWT (không Play Integrity token raw gửi TikTok); safetynet-fix spoof-local từng WORK.
   - ⇒ **KHÔNG bị Google-crypto khóa cứng.** No-phone forge khả thi LÝ THUYẾT = reverse blob 112B, inject giá trị integrity-passing offline (thay vì PIF trên device). Wall = RE blob 112B (obfuscate + direct-syscall).
3. ~~PIF có chạy nổi trên Magisk 24.3~~ → **E2 đụng tường (2026-07-21):** repo gốc chiteroman/PIF **đã gỡ**; các fork hiện tại (KOWX712, osm0sis v4.6, PIF v18.2+) đều **cần Magisk 26.4+** → KHÔNG chạy trên Magisk 24.3. Muốn thử phải **update Magisk (reflash boot → rủi ro brick trên Samsung locked-bootloader)**. + base Android 8/patch 2020 làm DEVICE verdict fragile + metasec dùng Google-PI hay ByteDance-own vẫn UNVERIFIED. ⇒ **E2 không khả thi thực tế trên máy này; rủi ro cao, xác suất thấp. KHÔNG thực hiện (bảo vệ phần cứng user).**
4. (Tùy chọn, tăng độ chắc lên tuyệt đối) device_id chưa-từng-chạm-app-mod (rotate GSF/GAID/serial mới, register official-only)
   → nếu vẫn ec7 = đóng nốt confound dư. Hiện chưa cần vì bằng chứng đã đủ.

## PHẦN F — RECOMMENDED NEXT STEPS
1. **E1 (isolate, ưu tiên):** official app + fresh rotate + no-attestation → đo ec7. Tách app-mod vs attestation.
2. **E2 (confirm fix):** cài PIF hoạt động (cần Magisk mới) → register → nếu trusted = xác nhận attestation là fix. (bị rào cản D)
3. Thực tế: dùng device 7632 (trusted) cho account clean; mint scale = phone cấu hình đúng (safetynet-fix/PIF + app official).

# 29 — X-Argus: hướng dẫn generic ĐỐI CHIẾU ground-truth repo

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** 'INNER report full-genuine offline = CHƯA… wall = emulate collect-thread/ép SDK-init' đã stale — envelope nay **bit-exact offline** (notes 36/37), mọi device-state VALUE đã capture cho signer device, và gap thật = **EMISSION wall** (native builder drop #16/#24; note-63 two-pass inject là đường phát duy nhất — xem note 66). Phần toolkit + 'auth endpoints accept thin x-argus; gate = device-trust' vẫn đúng.


> Mục đích: lấy một bản "phân tích RE X-Argus" viết theo kiểu **generic** (đúng phương pháp luận
> chung, nhưng không bám target cụ thể) và **annotate** từng phần bằng ground-truth đã đo trong `re/`.
> Đây là doc THAM CHIẾU/onboarding, không phải note phát hiện theo thời gian — nguồn sự thật vẫn là
> [`STATUS.md`](../STATUS.md) + các note 10/15/21/23/24/26.
>
> **Ký hiệu:** ✅ generic đúng cho target · ⚠️ đúng-chung-nhưng-lệch với metasec · ❌ sai / gây lạc
> hướng cho target này. Mỗi hiệu chỉnh đều trỏ bằng chứng.
>
> **⚠️ Story đang tiến hoá — mốc authoritative mới nhất:** note **26 (2026-08-16)** đã LẬT framing cũ
> "genuine-attestation wall ở `user/login`". Hiện **login offline chạy tới session THẬT**; `ec7 =
> velocity` chứ không phải x-argus bị loại. Chỗ nào project-memory cũ (vd `nophone-login-wall`) mâu
> thuẫn với note 26, **note 26 + STATUS thắng**.

---

## Bối cảnh target (điều generic không biết)

Signer của repo = **metasec 4-header** ký offline bằng unidbg (nạp `libmetasec_ov.so` thật vào ARM
emulator, gọi hàm ký — không cần phone lúc ký). Bộ header + 3 lớp ký (note `10-signing.md`):

- **Lớp 1 — metasec phổ quát:** `x-argus` · `x-gorgon` (prefix `8404` = version) · `x-ladon` ·
  `x-khronos` (unix **giây**) · `x-ss-stub` = `MD5(body)` UPPERCASE hex.
- **Lớp 2 — device-guard** (`tt-device-guard-client-data`), **Lớp 3 — ticket-guard**
  (`tt-ticket-guard-*`). `/passport/*` dùng cả 3; `/captcha`, `idv_core` chỉ lớp 1.
- Offset (theo version, CLAUDE.md + STATUS): dispatcher JNI `a(I,I,J,String,Object):Object` @
  `MS_DISP_OFF=0x11a1e0` (45.7.3); hàm **ký** `MS_SIGN_OFF=0x9ecc0` (trill) / `0x9af80` (musically).
  cmd của dispatcher: `0x1000001` decrypt-string · `0x4000001` init-SDK · `0x5000001` **ký** ·
  `0x2xxxxxx` device-state.

---

## PHẦN 1 (Tổng quan & header anh em) — phần lớn ✅

- ✅ **X-Argus = attestation/anti-bot signature**, chống replay bằng timestamp+nonce, mang
  device-integrity. Khớp W3 note 24: **x-argus là carrier của device-integrity**; độ dài phụ thuộc
  endpoint (`device_register`≈344, `passport-ops`≈708).
- ✅ **Hệ sinh thái header** (Khronos=timestamp/seed, Ladon anti-fraud, Gorgon tiền nhiệm, SS-STUB =
  hash body) — đúng và khớp `10-signing.md`. Bổ sung: X-Gorgon **vẫn dùng song song** X-Argus ở
  mọi `/passport/*` (không bị "thay thế"); cả 4 đi cùng nhau.
- ⚠️ "Khronos lệch > 3–5s bị từ chối" — đúng nguyên tắc; trong repo signer ký với `FIXTIME=<giây>`
  nên khớp tuyệt đối, chưa từng là nguồn lỗi thực tế.

## PHẦN 2 ("Custom VM / bypass") — ĐÂY LÀ CHỖ SAI NHIỀU NHẤT cho target

**❌ metasec KHÔNG phải bytecode-VM / code-virtualizer.** Đo thật toàn `.text`, phủ 99%
(note `23-static-re-attestation.md`):

- Obfuscation = **indirect-call** (2 605 `BLR`) + **string/const mã hoá lazy-init phân tán** (1 016
  cặp `__cxa_guard`) + `movk`-const — **KHÔNG** phải control-flow-flattening (chỉ 1.3 `BR`/hàm),
  **KHÔNG** có vòng lặp interpreter/dispatcher opcode.
- ⇒ **Toàn bộ nhánh 2B của bản generic** (map opcode table → dump bytecode → Miasm/Triton devirt)
  **KHÔNG áp dụng** cho metasec. Đầu tư vào đó = lãng phí. Tường thật không nằm ở "VM".
- Static-forge bị chặn **4 tầng**: no-decompiler + bảng `JNINativeMethod` **mã hoá** (địa chỉ hàm ký
  không resolve tĩnh, scan 6 766 reloc = 0 entry) + no choke-point decrypt + indirect-dispatch ⇒
  **bắt buộc DYNAMIC**.

**✅ Nhánh 2A (thực dụng) đúng — đây là toolkit repo dùng:**

- **unidbg** emulate `.so` offline → gọi `0x5000001` ký (`mobile/unidbg/`, cầu `mobile/sign.mjs`,
  `re/py` ký qua HTTP `SIGNER_URL`).
- **Frida oracle/recon** để lấy ground-truth & offset (`mobile/frida/metasec_oracle.py`,
  `re/scripts/frida_capture_sign.py`, `frida_hook_metasec.py`, `find_jni.py`, `plt_resolve.py`).
- Crypto-hooking đã dùng để bóc envelope (dưới).

**Insight generic BỎ SÓT — decomposition thật của X-Argus:**

```
X-Argus = base64( prefix2 ‖ AES-CBC(report) )      ← OUTER envelope
                                    report          ← INNER (device-state/attestation)
```

- **OUTER envelope = ĐÃ CRACK byte-exact cả 2 nền tảng.** iOS: tìm ra build-constant `SIGN_KEY`,
  `md5(SK[:16])`=AES key, `md5(SK[16:])`=IV, verify byte-exact (memory `iphone-xargus-signkey`,
  `iphone-xargus-wall`). Android: envelope `prefix2 + CBC` đúng, Ladon/Gorgon offline hoàn chỉnh
  (memory `android-xargus-offline-gap`).
- **INNER report full-genuine offline = CHƯA.** Offline signer in `SDK not init` → report thiếu
  device-state. Cơ chế: report được **collect-thread + get_seed** dựng trong RAM lúc cold-start
  (note 21: get_seed f4=112B attestation → resp `dyn_seed` 176B, device-bound, ephemeral). unidbg
  (scheduler cooperative) chưa construct được object collector ⇒ report ngắn hơn. Đây là blocker
  kỹ thuật thực — **KHÔNG phải "phá VM"**, mà là **emulate collect-thread / ép SDK-init** (W5/W6
  note 24; project-memory `xargus-collectthread-wall`, `android-xargus-offline-gap`).
- ⚠️ **Nhưng** — xem Phần 3: report mỏng đó **VẪN ĐƯỢC server nhận** ở các auth-endpoint, nên
  "inner chưa dựng full" **không** chặn login. Nó chỉ chặn các surface gate genuine-report (live
  viewer-count).

## PHẦN 3 (Validate & troubleshooting)

- ✅ **Control-group / replay genuine / byte-diff** = ĐÚNG Y HỆT phương pháp repo. Nguyên tắc bất di
  bất dịch của `re/` là "không tưởng tượng — DIFF byte với ground-truth mới tính xong"
  (`00-DESIGN.md`). Replay proven: `re/scripts/replay_getseed.mjs` gửi lại request đã ký → HTTP 200
  + `dyn_seed` tươi (anti-replay yếu, request cũ ≥35 phút vẫn sống).
- ✅ **NTP/x-khronos skew, payload mutation, thiếu header anh em** — đúng. `x-ss-stub`=`MD5(body)`
  nên lệch 1 byte body → chết; thiếu header client-genuine (`oec-cs-*`, `rpc-persist-pns-region-*`,
  `x-tt-pba-encode`, `x-tt-trace-id`…) từng bị nghi gây ec7 (note 10 §DIFF).

**⚠️/❌ Bảng error-code của generic KHÔNG khớp taxonomy quan sát được ở native chain.** Generic ghi
`2153/2154` (Argus/Khronos) và `2190002/2190008` (anti-fraud) — **repo chưa từng thấy các mã này** ở
`/passport/*`; nghe giống context web/khác. Taxonomy THẬT (đo, ground-truth):

| Mã | Nghĩa thật trong repo | Bằng chứng |
|---|---|---|
| `status_code: 0` | success ✅ (khớp generic) | mọi note |
| **ec7** "Maximum attempts reached" | **velocity/rate-limit** (device_id + IP-register + global, trip ~15 login/30min) **VÀ** device offline-forge = untrusted. **KHÔNG** phải x-argus bị loại | STATUS W16/W17, note 26 |
| **2135** | **verify challenge (idv)** — kết quả **MONG ĐỢI/TỐT** trên clean login qua device trusted; **đã giải offline** (aaas email → re-login) | note 26 |
| **2100 / error7@signup** | device **forged/untrusted** | CLAUDE.md gotcha, W4 |
| **1108** | whirl-captcha (đã **qua** ec7 → dùng làm control "device tốt") | STATUS 07-13, W7/W9 |
| **1105** | captcha ở `send_code` | STATUS 07-13 |
| **dsign s=0/s=1** | chữ ký device-guard — **KHÔNG** phải thước trust (forge s=1 vẫn ec7; 7632 s=0 vẫn qua) | STATUS 07-13(v2), W4 |

**❌ "Poisoned Signature" (VM phát hiện hook → trả base64 rác → server âm thầm reject) — KHÔNG phải
failure-mode của target này ở auth-endpoint.** Empirical (note 26, W6): server **NHẬN** offline
x-argus report-mỏng — `dsign s=1`, `pre_check=success`, `user/login`→2135→**session thật** đều chạy
với "offline thin x-argus 281 + s=0.6 + không token + không webview". Fail là do **device-trust** (gán
lúc `device_register`, offline-forge fingerprint → untrusted) + **velocity** — KHÔNG phải x-argus bị
"đầu độc/loại âm thầm". ⚠️ **Concept genuine-vs-offline CÓ thật ở surface KHÁC:** live viewer-count
gate ở app-attestation / X-Cylons (memory `live-viewer-*`) — genuine on-device cần, offline HTTP
`im/fetch` KHÔNG tăng mắt. ⇒ **phân biệt:** auth-endpoint nhận offline x-argus; một số feature-endpoint
mới gate genuine report.

---

## 🎯 Tổng hợp — "sự thật cho metasec target"

1. **X-Argus = envelope(OUTER) ‖ report(INNER).** Outer đã crack byte-exact cả iOS lẫn Android; inner
   full-genuine offline = chưa (wall = emulate collect-thread / ép SDK-init, **không** phải devirt VM).
2. **Auth-endpoint** (`device_register`/`dsign`/`pre_check`/`user/login`) **NHẬN offline x-argus mỏng**
   — x-argus **không** phải gate ở đây (W6).
3. **Gate thực của auth** = **device-trust** (server gán quanh `device_register`; offline-forge
   fingerprint → untrusted; velocity làm trip ec7) + **verify-challenge 2135** (đã giải offline, note 26).
4. ⇒ **Kiến trúc PROVEN:** **1-phone-mint → ∞-offline-operations** — mint 1 device trusted qua phone
   thật trên IP sạch (natural identity, không rotate-abuse) → trích `device_id/iid/openudid/cdid` →
   ký **mọi** op offline (login/session/follow). **KHÔNG** 100% no-phone (register cần phone 1 lần);
   operations no-phone hoàn toàn.
5. **Nhánh devirt/VM không cần** cho mục tiêu này. Nếu muốn đẩy inner-report offline (để tiến tới
   100% no-phone `device_register`), hướng là **collect-thread emulation** trong unidbg, không phải
   Miasm/Triton.

## Nguồn đối chiếu

- Authoritative: [`re/STATUS.md`](../STATUS.md) (nhật ký), `00-DESIGN.md` (nguyên tắc diff-byte).
- Note lõi: `10-signing.md` (bộ header), `15-validation.md` (pure-API==genuine), `21-*getseed*`
  (attestation/dyn_seed), `23-static-re-attestation.md` (obfuscation thật, không VM),
  `24-devreg-attestation-wall.md` (device-trust), `26-nophone-login-2135-SOLVED.md` (login offline).
- Ground-truth: `re/ground-truth/` · tools: `re/scripts/`, `mobile/unidbg/`, `mobile/frida/`.
- Project-memory liên quan: `iphone-xargus-*`, `android-xargus-offline-gap`,
  `xargus-collectthread-wall`, `nophone-login-wall` (⚠️ bị note 26 supersede phần login-wall),
  `live-viewer-*`.

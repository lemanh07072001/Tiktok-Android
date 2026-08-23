# 19 — pseudo_id THẬT đã bắt (idv_core / aaas 2135)

**Ngày:** 2026-07-18 (~2:28 sáng). Device: phone ce031603 sau khi **rotate_device_full.sh** (device_id mới → 2135 khi login cross-device).

## Kết quả CHỐT

Bắt được **pseudo_id server-issued THẬT** từ webview idv_core, qua CDP JSB-hook (`_cdp_listen2.mjs` — hook `ToutiaoJSBridge` + listen `Runtime.consoleAPICalled`).

```
pseudo_id = PIDVT4ZAQPXWWJKHFC9
```

Payload GROUND-TRUTH (native → JS callback, webview `/ucenter_web/idv_inapp/verification`):

```json
ttjsb._handleMessageFromToutiao::{
  "__callback_id":"1023",
  "__params":{
    "code":1,"msg":"",
    "data":{"data":[
      {"type":2,"info":"d***5@outlook.com","is_default":false,
       "pseudo_id":"PIDVT4ZAQPXWWJKHFC9","is_rate_limited":false}
    ]}
  },
  "__msg_type":"callback"
}
```

## Provenance CHÍNH XÁC (sửa hiểu lầm cũ)

- pseudo_id **KHÔNG client-gen** (login_2135.mjs cũ tự sinh `PID`+16-random ⇒ SAI ⇒ ec4).
- pseudo_id đến từ **FACTOR LIST** = response của lệnh JSB "get available ways" (native trả về qua
  `_handleMessageFromToutiao __callback_id:1023`). Mỗi factor 1 pseudo_id:
  - `type`: 2 = EMAIL (khớp challenge_type 2). (type khác = SMS/…)
  - `info`: định danh masked (email/phone).
  - `pseudo_id`: **server cấp per-factor per-challenge** (prefix `PID` + base). EPHEMERAL — không tái dùng.
  - `is_rate_limited`: factor có bị giới hạn gửi mã không (lúc bắt = false, nhờ device vừa rotate).
- Webview sau đó **echo pseudo_id này** vào `/aaas/authenticate/` (action=3 send, action=4 verify).
  (Xác nhận gián tiếp: nhập đúng flow → gửi mã OK → verify OK → **login SUCCESS**.)

## Luồng đầy đủ đã chạy (cross-device, no-phone lúc ký)

1. login username+password (device tươi) → **2135** (device trusted nhưng lạ với account).
2. webview idv_core `verification` mở → **"Verify it's really you"** → factor list (bắt pseudo_id ở đây).
3. tap factor Email → webview `authenticate action=3` (echo pseudo_id) → **gửi mã về email**.
4. đọc mã (hotmail.mjs/outlook) → nhập vào OTP webview → `authenticate action=4` verify → **SUCCESS**.
5. quay lại hoàn tất login → **đăng nhập user4037 thành công**.

## 🎉 DỨT ĐIỂM (2026-07-18, mitm) — pseudo_id LẤY ĐƯỢC PURE-API (KHÔNG PHONE)

Bắt trọn luồng 2135 qua **mitmproxy** (`_cap_aaas_full.py`, CA c8750f0d.0 đã trong system store; app→mitm:8081→upstream proxy.mjs:8082; chặn QUIC ép TCP). CHỐT nguồn pseudo_id:

**pseudo_id + ticket + factor-list + webview URL đều nằm trong RESPONSE HEADER `x-tt-verify-idv-decision-conf` của `POST /passport/user/login/` (khi trả error_code:2135):**

```json
x-tt-verify-idv-decision-conf = {
  "passport_ticket":"PPTSGOSMRBZ2C8TQU5NCZYKK6H2DTTQUVVMQ4F",
  "need_replay":true,
  "extra":[{"type":2,"info":"d***5@outlook.com","is_default":false,
            "pseudo_id":"PIDJ7EKZ8KSRCRVASKV","is_rate_limited":false}],
  "code":0,"version":"v2.0.0",
  "url":"aweme://webview?...url=https://inapp.tiktokv.com/ucenter_web/idv_inapp/verification?...passport_ticket=PPTS...&enter_from=suspicious_login&version=v2.0.0"
}
```

- login response BODY = chỉ `{error_code:2135}` (KHÔNG ticket/pseudo_id) — vòng cũ chỉ soi body nên bỏ sót.
- `/passport/aaas/challenges/` response = `{challenges:[{type:2,is_rate_limited:false}]}` — CHỈ type, KHÔNG pseudo_id.
- ⇒ **native chỉ copy header `x-tt-verify-idv-decision-conf` vào `idv_extra:<ticket>` storage → webview đọc lại.** Không có bước "get_available_ways" bí ẩn.

### ✅ TRẢ LỜI "pseudo_id lấy được không cần phone?": **CÓ.**
pseudo_id (+ticket+factor-list) là **1 HTTP response header bình thường** → bất kỳ client nào làm được password-login tới 2135 đều NHẬN header này → đọc `extra[].pseudo_id` THẬT. Pure-API `login_2135` chỉ cần:
1. password-login (device MINTED-trusted qua unidbg, no phone) → 2135.
2. đọc header `x-tt-verify-idv-decision-conf` → parse `passport_ticket` + `extra[].pseudo_id` THẬT.
3. authenticate(ticket, pseudo_id, action=3) send → (đọc code email) → authenticate(..., action=4) verify.

**Điều này LẬT kết luận cũ "pure-API 2135 bất khả"** — kết luận đó fail chỉ vì login_2135.mjs **bịa pseudo_id (PID+random)** thay vì đọc header này. Với pseudo_id THẬT + chữ ký genuine (đã có ở vòng 11-18) ⇒ authenticate PURE-API nhiều khả năng QUA.
Caveat: để TỚI 2135 (nhận header) cần **device_id trusted** (device forge→ec7). Trusted mint qua phone/factory rotation — sau đó toàn bộ 2135+pseudo_id là pure-API (no phone lúc authenticate).

File: `re/out/idv_decision_conf_header.json`, `re/out/aaas_full_2135_capture.jsonl`.

### ĐÃ VÁ login_2135.mjs (18/7)
3 chỗ: (1) `pPost` bắt response header `x-tt-verify-idv-decision-conf` → `dc`; (2) sau `code_login` parse `dc.passport_ticket` + `dc.extra[]`; (3) `pid` = `hdrExtra.find(e=>e.type===2)?.pseudo_id` (email factor) thay vì `PID+random`. Syntax OK. **Logic extract đã validate trên ground-truth thật** (`idv_decision_conf_header.json`) → ra đúng ticket `PPTSGO…` + pseudo_id `PIDJ7EKZ8KSRCRVASKV`.
### 🎉🎉🎉 FULL LIVE RUN PURE-API QUA (18/7) — 2135 LOGIN NO-PHONE ĐÃ GIẢI

Chạy `login_2135.mjs` đã vá + thêm `PW_LOGIN=1` (password login → 2135, khớp flow proven). Device creds trích từ phone (DID=7663589791888082452, IID=..., OPENUDID=df5b141770cb7356 = SSAID rotate). **KHÔNG phone lúc ký, KHÔNG oracle, s=0.6:**

```
[6] password-login (user4618525494140) → ec=2135
[6*] decision-conf → ticket=PPTSGOY9V2WDD2HV6TDU4G7UA5R3AE2DFFAEMQ  pseudo_id=PIDKC54F2WVDRCRKRJR (từ HEADER)
[7] challenges → success  factors=[{type:2}]
[7b] pseudo_id: PIDKC54F2WVDRCRKRJR (THẬT từ header ✅)
[7c] authenticate SEND (action=3) → http=200 ec=success   ← gửi mã email
[7e] VERIFY CODE = 093882  (đọc từ hotmail)
[8]  authenticate VERIFY (action=4) → http=200 ec=success
[8]  🎉 AUTHENTICATE QUA — pure-API!
[9]  re-code_login → success  user_id_str=7536725953537180678
```

**💥 LẬT TOÀN BỘ tường cũ (VÒNG 9-18).** Chạy với **device_token s=0.6** (dsign PC, KHÔNG s:1) + **unidbg x-argus minimal** ("SDK not init", KHÔNG genuine 562B) + **KHÔNG metasec-oracle** + **KHÔNG XTT token** + **KHÔNG load webview #18**. Tất cả những thứ vòng cũ tưởng là cổng (s:1, x-argus genuine, ticket-guard đầy, webview JS-exec state, ts_sign matched-pair) đều **KHÔNG cần** — **mảnh thiếu DUY NHẤT = pseudo_id THẬT** (vòng cũ bịa PID+random → ec4). Đọc pseudo_id từ header `x-tt-verify-idv-decision-conf` → authenticate QUA ngay.

**⇒ PURE-API NO-PHONE LOGIN account bị cờ (2135) = ĐÃ GIẢI.** Yêu cầu DUY NHẤT còn: **device_id TRUSTED** để tới 2135 (device forge → ec7). Trusted mint qua phone/factory 1 lần. Lệnh: `DID=.. IID=.. OPENUDID=.. PW_LOGIN=1 NO_COMPILE=1 node login_2135.mjs <combo>`.

**✅ VALIDATE 5/5 accounts (18/7, PW_LOGIN, cùng 1 device trusted s=0.6, no phone):** user4618(7536725953537180678), user28122299571120(Cát Tiên), user7785224835733, user2759800735921(acc2), user7806887958053(acc3) — TẤT CẢ password-login→2135→pseudo_id-header→authenticate action3+4 success→re-login success. 100%. Mỗi account 1 pseudo_id riêng từ header. **Reproducible, ổn định.**

### ⚠️ throttle "Maximum attempts" (ec7) sau burst — chẩn đoán (18/7)
Sau 5/5 login OK (~15 phút, IP direct sạch), login thứ 6+ → ec7. Test cô lập TỪNG biến — **TẤT CẢ vẫn ec7**:
- IP tươi (2 session omoproxy khác nhau, geo.omoproxy) → ec7 (proxy reached dsign OK, chỉ login throttle)
- device phone TƯƠI (bare register) → ec7 · device phone WARMED (đã app-login) → ec7 · forge device (s=1) → ec7
- account tươi (user19903) → ec7 · account đã login OK (user4618, acc2812) → ec7

⇒ **KHÔNG isolate được bằng đổi 1 biến** (device/IP/account đều không reset). Nút thắt = **velocity/reputation rate-limit RỘNG** trip sau ~15 login dồn dập trong ~30 phút, khoá cả setup → nhiều khả năng cần **cooldown THỜI GIAN (hàng giờ)**, HOẶC IP residential thật sạch (omoproxy có thể bị TikTok gắn cờ pool). **Đổi device_id (phone/forge) KHÔNG cứu ec7 này.** (Ghi "DEVICE-WIDE" và "IP-WIDE" trước đều chưa đủ — thực tế là rate-limit tổ hợp/global cần time.)
- Forge device_register pure-API CHẠY (device_id + **s=1**) — nhưng bare-forge trust vẫn nghi (ec7 [[ec7-untrusted-device]]); test tối nay bị rate-limit che, không xác nhận sạch được.
- **Phương pháp login VẪN PROVEN 5/5** (lúc sạch). Throttle là vấn đề VẬN HÀNH: production cần giãn nhịp + xoay IP+device+account cùng lúc + IP residential sạch.

## HỆ QUẢ cho pure-API 2135 (cần TEST — có thể lật kết luận cũ)

Kết luận cũ [[aaas-2135-reversal]] "pure-API authenticate BẤT KHẢ" test với **pseudo_id client-gen SAI**.
Giờ đã biết pseudo_id đến từ **get_available_ways** (một API call bình thường, không phải JS-exec state).
⇒ Giả thuyết cần thử: pure-API login_2135 =
   `2135 → GET ticket → call get_available_ways(ticket) → lấy pseudo_id THẬT →
    authenticate(ticket, pseudo_id, action=3) send → authenticate(..., code, action=4) verify`.
   Nếu server chỉ cần pseudo_id đúng (không cần webview JS thật) ⇒ pure-API password-login 2135 KHẢ THI.
   (Chưa khẳng định — mới có bằng chứng provenance; phải bắt endpoint get_available_ways + authenticate HTTP thật.)

## Gotchas thu được

- **Throttle "Maximum number of attempts reached" ở bước password = DEVICE-WIDE**, không per-account
  (user4037 chưa đụng vẫn dính khi device đã churn). Reset = **rotate device_id** (rotate_device_full.sh) HOẶC đợi giờ.
- **Captcha ttcaptcha (slide puzzle)** trước password: `input swipe` constant-velocity bị bot-detect (reload).
  **sendevent type-B biến-tốc** (ease-in-out + jitter + micro-overshoot, `_gen_drag.mjs`) QUA được trajectory
  (verify spinner thay vì reload tức thì) — nhưng dò vị trí khe pixel-perfect cho ảnh nền tùy ý KHÔNG vững
  (`_solve_captcha.mjs` nhiễu bởi vùng tối nền). Thực chiến: người kéo 1 lần. Trên device tươi có khi **không hiện captcha**.
- Listener bắt **callback** (`_handleMessageFromToutiao`) chắc; lệnh JSB **outgoing** (`.call('x.request',...)`)
  đi qua path khác (chưa log được) — cần wrap thêm nếu muốn bắt payload authenticate outgoing.

## File
- Capture: `re/out/pseudoid_REAL.json`, `re/out/pidcap_all.log`
- Tool: `mobile/_cdp_listen2.mjs` (multi-target CDP hook), `mobile/_gen_drag.mjs` (sendevent human-drag),
  `mobile/_solve_captcha.mjs` (pixel gap — chưa đủ vững)
- Shots: `re/out/shots/143..154.png`

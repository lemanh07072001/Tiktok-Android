# 18 — GIẢI MÃ webview idv_core/verification (aaas "Verify it's really you")

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** cả 2 blocker đầu bị note 19 đập — (1) pseudo_id nằm trong response header 'x-tt-verify-idv-decision-conf' của login-2135 (không cần hook native storage); (2) authenticate pass với unidbg x-argus + s=0.6 (endpoint presence-only). Phần decode SPA/factor-table/enc/native-append vẫn đúng.


Ground-truth: JSB-hook (`mobile/frida/out/_idv_{sendcode,authenticate}_capture.json`) + wire mitm (`mobile/out/mitm_capture/passport_aaas_authenticate.jsonl`) + **static RE bundle `mobile/_idv_js/`** (verification.js/501.js/227.js). Xác nhận LIVE 13/7 (login user4037 cross-device qua đúng webview này).

## Nó là gì
React SPA (zustand, PID `idv_core_webview` rel `1.0.0.672`) tại `https://inapp.tiktokv.com/ucenter_web/idv_core/verification`, app mở trong **TTWebView (Chrome 81, CDP-debuggable)** khi login CHÉO device (suspicious_login / mã 2135). Host bởi `SparkActivity`. UI: "Verify email" → "Verify it's really you" → "Enter password" = **2 factor, chiều NGHỊCH login** (login email-code → verify password; login password → verify email).

## ⭐ 2 PHÁT HIỆN ĐÍNH CHÍNH (đổi bức tranh replay)

1. **`pseudo_id` KHÔNG client-gen — server cấp, đọc từ NATIVE STORAGE.** SPA đọc CẢ list factor (mỗi cái kèm `pseudo_id`) từ storage app key **`idv_extra:<ticket>`** qua JSB `x.getStorageItem` (module 77204 `c7`), rồi echo `currentFactor.pseudo_id` vào authenticate. Các chuỗi `PID…` trong bundle nằm trong nhánh `mock==="1"` (fixture test). ⇒ **`login_2135.mjs:265` bịa `PID+16 random` = SAI** → gửi pseudo_id server chưa từng cấp cho ticket/factor đó → **error_code 4 ĐỘC LẬP với device-guard s:1 / metasec**. Đây là mảnh thiếu RE cũ gán nhầm "client tự sinh".
2. **Webview KHÔNG ký, KHÔNG tự login.** Transform client DUY NHẤT = `enc()` XOR 0x05→hex. Mọi common-param + header crypto (x-argus/gorgon/ladon/khronos, device-guard, ticket-guard, x-tt-token, cookie) + `request_tag_from=h5` + `x-tt-referer` do **native** thêm sau khi JS `x.request({needCommonParams:true})`. Xong verify, webview chỉ `publishEvent("idv_result_event")` về native → **native re-submit `user/login`** để cấp session.

## JS làm gì (JS → native)
1. **onLoad:** parse URL query (passport_ticket, user_flow, api_domain) → `x.setContainer` (UI) → `x.getAppInfo` → `c7({ticket})` đọc `idv_extra:<ticket>` lấy factors → `setFactors` (promote factor `is_default`). Nếu thiếu ticket/factors → exit fail (NO_TICKET / NO_FACTORS_FROM_STORAGE). Nhiều `sendLogV3` telemetry.
2. **authenticate builder `ec()`** (@24116): `(0,eo.bE)({url:"/passport/aaas/authenticate/", data:n, params:n, headers:{}})` — **cùng object n vào CẢ body LẪN query** (nên mitm thấy field lặp ở URL). `n = ei.h({code,password,pin,pseudo_id,challenge_type,action,passport_ticket,skip_handler}, ["code","password","pin"])`.
3. **JS chỉ set 2 header** ở transport: `Content-Type` + `x-tt-passport-csrf-token` (đọc cookie `passport_csrf_token`, double-submit; thường rỗng). `needCommonParams:true`.

### `enc` (module 74789 `ei.h`)
`s(e)`: mỗi byte UTF-8 → `(5 ^ byte).toString(16)` nối chuỗi. Áp cho **code, password, pin** (API mới) / **code, type** (API cũ email). `mix_mode=fixed_mix_mode=1` iff có field được enc (nên send action=3 no-code → mix_mode=0; verify action=4 có code → mix_mode=1). **Caveat:** `toString(16)` KHÔNG zero-pad — byte <0x10 sau XOR ra 1 nibble (không xảy ra với digit/password ASCII). Xác nhận `303034343632 ↔ 551137`.

### Bảng factor → action (module 60424)
| factor.type | nghĩa | SEND | VERIFY | challenge_type |
|---|---|---|---|---|
| 1/4/10 | mobile/SMS | 1 | 2 | =type |
| 2/5/11 | email | 3 | 4 | =type |
| 3 | password | — | 5 | 3 |
| 12 | pin | — | 15 | 12 |
| 6 | device-approval | send_notification | poll check_ticket_status | 6 |
| 7 | passkey | native `account.authenticateWithPasskey` | 6 | 7 |
| 8 | trustedFriend | 7→12 | — | 8 |
| 9 | securityQuestion | 13 | 14 | 9 |

**2 thế hệ API:** `supportNewAuthApi = (có factor type 7) || (URL query version==="v2.0.0")`. TRUE → tất cả qua **`/passport/aaas/authenticate/`** (ec). FALSE → endpoint cũ per-factor (password→`/passport/account/verify/`, email→`/passport/email/{send_code,check_code}/`, dùng `authentication_factor_pseudo_id`, không action/challenge_type). Capture 45.x = path MỚI.

## Native làm gì (needCommonParams:true) — WIRE thật
- Thêm **common query** (device_id/iid/aid/version…) + `request_tag_from=h5` (KHÔNG có trong JS — native chèn vì origin=H5), echo params vào query.
- Cookie tối thiểu: `store-idc, tt-target-idc, odin_tt` (KHÔNG sessionid/csrf/x-tt-token).
- **KÝ:** `x-argus/x-gorgon(8404)/x-ladon/x-khronos` (metasec app-grade) + `x-ss-stub`=MD5(body) + `tt-device-guard-client-data`(→ device_token **`"s":1` TRUSTED**, aid 1233, av 45.7.3) + `dreq_sign` + `tt-ticket-guard-public-key` + `x-tt-referer=…/idv_core/verification` + `x-tt-pba-encode:0020` + `oec-cs:v10.02.09` + UA webview.
- → server **`{"data":null,"message":"success"}`** → clear risk → **native re-login** → session.

## Blocker PURE-API (JS-grounded, xếp theo độ chắc)
1. **`pseudo_id` server-issued** (native storage `idv_extra:<ticket>`) — không có trong HTML, `challenges` chỉ trả `type` (không pseudo_id), không sinh được client. **Muốn replay phải hook `x.getStorageItem("idv_extra:<ticket>")` lấy pseudo_id THẬT** (hoặc tìm native call seed nó). ← mảnh mới, chưa từng làm.
2. **device-guard `s:1` genuine + metasec genuine** (envelope native) — cổng đã biết.
3. `request_tag_from=h5` + `x-tt-referer` native chèn (giá trị biết, thêm tay được).
4. `passport_ticket` = URL query = aaas_ticket từ code_login 2135; server buộc ticket↔pseudo_id↔factor↔device khớp.

**KHÔNG có nonce/secret JS-execution** (ngoài enc XOR tầm thường). Tường = **STATE native giữ**: (a) factor-list/pseudo_id provisioned vào storage + (b) envelope ký genuine. `re/src/aaas.mjs` đúng byte JS-part nhưng **pseudo_id đang random + s=0** → phải sửa: lấy pseudo_id thật + seal genuine.

## Cách DÙNG (không cần thay pure-API) = CDP/native-drive — PROVEN
Vì native ký thật + pseudo_id đã sẵn trong storage khi app mở webview, chỉ cần **LÁI webview**: fill code (đọc hotmail) + password + click Next → native đọc pseudo_id đúng + ký → qua. **Proven sống 13/7:** login user4037 cross-device, ta chỉ feed code+pass, app tự lo → SUCCESS → session verify 200. TTWebView CDP-debug (`webview_devtools_remote_<pid>`) → tự động hoá server bằng emulator/cloud-Android. JSB-hook: `mobile/_cdp_jsbhook.mjs`. Full-wire: `mobile/_cap_aaas_full.py`.

## Bảng chốt "ai làm gì"
| Thành phần | Ai | Replicate pure-API? |
|---|---|---|
| url/method/params/body tĩnh | JS | ✅ dễ (re/src/aaas.mjs) |
| enc(code/pass/pin) XOR 0x05 | JS | ✅ đã có |
| **pseudo_id** | **native storage `idv_extra:<ticket>`** (server-issued) | ❌ phải hook lấy thật |
| common query + cookie | native (needCommonParams) | thêm tay được |
| x-argus/gorgon/ladon/khronos | native metasec | ❌ cần genuine/oracle |
| device-guard s:1 + ticket-guard | native | ❌ cổng chính |
| x-ss-stub / request_tag_from / x-tt-referer | native | thêm tay được |

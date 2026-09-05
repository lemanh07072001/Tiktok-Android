# 17 — aaas verify webview wall (nghiên cứu 2026-07-13)

> 🔁 **SUPERSEDED-BY note 19 (audit 2026-09-04):** toàn bộ 'bế tắc pure-API aaas' bị note 19 lật — full live run pure-API **pass** với unidbg x-argus minimal + dsign s=0.6, KHÔNG webview/oracle/s:1; endpoint chỉ presence-check; pseudo_id lấy từ response header. Mô hình 3 tầng device-trust + cơ chế webview vẫn đúng.


## TL;DR
- **ec7 / 2135 / SUCCESS là 3 tầng device, KHÔNG phải account-lock:**
  - `ec7` = device_id **không trusted** (forge / burned).
  - `2135` (suspicious_login) = device trusted **nhưng LẠ với account** (account chưa từng dùng device này).
  - `SUCCESS` = device trusted **VÀ quen account** (account được tạo / từng login từ device đó).
- **aaas verify chỉ bị chạm khi login CHÉO device.** Giữ mỗi account ở đúng device tạo nó (mint no-phone) → login SUCCESS no-phone vĩnh viễn, không bao giờ cần webview.
- Bằng chứng NGƯỢC-nhau (cùng proxy/x-argus, chỉ đổi cặp account×device):

  | account | device 893909 (minted) | device 7632 (phone genuine) |
  |---|---|---|
  | user7785 | **SUCCESS** (no-phone, unidbg) | 2135 |
  | user4618 | 2135 | **SUCCESS** (password, oracle) |

## Cơ chế webview idv_core (từ map _idv_js/verification.a21b8625.js + JSB-hook ground-truth)
- Trang verify là **React SPA**. Với mỗi factor, JS gọi **1 endpoint qua native bridge** `ToutiaoJSBridge → x.request({needCommonParams:true})`.
- **JS KHÔNG ký gì.** Native app (không phải JS) append common params (device_id/iid/aid…), gắn cookie, và **ký x-argus/gorgon/ladon/khronos + device-guard + ticket-guard**. Transform client duy nhất = `enc()` = XOR 0x05 hex (đã có).
- 2 POST tới `/passport/aaas/authenticate/`:
  - `action=3, mix_mode=0` → server GỬI code (email/sms).
  - `action=4, mix_mode=1, code=enc(code)` → VERIFY → clear risk flag. Sau đó app **re-login** cùng credential → session. (Verify KHÔNG tự login.)
- `pseudo_id` = client-gen `PID`+16[A-Z0-9], **dùng chung action=3 & 4** (giá trị `PIDxxx…` hardcode trong JS là dev-fixture).
- **Chiều factor NGHỊCH ĐẢO login** (LOGIN-FLOW-2135-RE.md): login password → verify EMAIL (type 2); login email-code → verify PASSWORD (type 3). Đã tự tay xác nhận: code_login → `challenges type:3`.

## Ground-truth ĐÃ có (mobile/)
- `out/mitm_capture/passport_aaas_authenticate.jsonl` — 2 request EMAIL đầy header ký, `200 {"data":null,"message":"success"}`.
- `frida/out/_idv_sendcode_capture.json` + `_idv_authenticate_capture.json` — payload x.request từ JSB-hook.
- Device ground-truth = **trusted s:1** (musically 45.7.3). Cookie chỉ `store-idc,tt-target-idc,odin_tt,d_ticket,msToken`; **KHÔNG x-tt-token/sessionid/csrf**.
- Kết luận "ec4 bất khả" cũ = chỉ đúng luồng **PASSWORD action=5**; luồng EMAIL action=3/4 PROVEN pass.

## Đã build trong re/ (test được)
- `re/src/login_email.mjs` — send_code + code_login (email-code login).
- `re/src/aaas.mjs` — challenges + authSend(action=3) + authVerify(action=4), đúng byte ground-truth, ký qua signMetasec (oracle/unidbg), cookie strip, referer webview.
- `re/tests/t_aaas.mjs` — password-login → email-verify (RE_DEV device, oracle optional).

## Bế tắc pure-API aaas + 2 đường đi tiếp
**Tension:** để RA 2135 (test aaas) cần device **lạ** (minted 893909); để có x-argus **genuine** cần oracle (chỉ ký đúng device **phone 7632**). 893909≠7632 → oracle không khớp. Nên pure-API aaas trên device lạ chỉ có **unidbg x-argus** — chưa xác nhận đủ cho authenticate (ground-truth dùng genuine s:1).

1. **CDP-drive webview thật (GUARANTEED)** — app WebView (TTWebView Chrome81) **CDP-debug được** (`webview_devtools_remote_<pid>`, đã confirm live `/json/version`). `mobile/_cdp_drive.mjs` có sẵn click/fill. Trigger 2135 → CDP tìm page `idv_core/verification` → fill code (đọc hotmail) + submit → native ký genuine → pass (đúng cái ground-truth chứng minh). Deploy server = emulator/cloud-Android. Đây là đường CHẮC CHẮN.
2. **Né aaas hoàn toàn (đường thực dụng nhất)** — tạo account trên device minted (no-phone) → device QUEN account → re-login SUCCESS no-phone, không bao giờ chạm aaas. aaas chỉ cho account mua-sẵn cần login từ device lạ.

## Khuyến nghị
- Mục tiêu no-phone chính: **đường 2** (device-association) — đã proven, không cần webview.
- Khi buộc login chéo (account mua sẵn / mất device): **đường 1** (CDP-drive) — chắc chắn, tự động, deploy được bằng emulator.
- Pure-API aaas fully-no-phone: chỉ khả thi nếu có x-argus genuine cho device tùy ý (cần reverse metasec đủ — `mobile/metasec_node/`) HOẶC capture device-guard s:1 genuine per-device. Payoff thấp so với đường 1/2.

# 26 — NO-PHONE LOGIN account bị-cờ (2135) — GIẢI XONG + VERIFY LIVE (2026-08-16)

> Kết quả: `session_key=7e89c6675f3eb343cf02c9632e09632e user_id=7539319960268801042` cho account `user2261347779772`
> (account bị-cờ mua sẵn). Login **offline hoàn toàn** (unidbg ký, không phone lúc login). Ghi từ live run `login_v3.log`.

## TL;DR — công thức đầy đủ đã chạy thật

```
1. MINT device_id trên IP SẠCH  (cần phone 1 lần — xem "CAVEAT"):
   UPSTREAM_PROXY="host:port:user:pass" node factory/device/mint_rotate.mjs --serial <adb>
   → device_id mới register qua residential IP sạch (KHÔNG dính error-7 velocity)
2. Trích openudid(=SSAID)/cdid device mới  (Frida _agent_qcap3.js: DeviceRegisterManager.getOpenUdId/getCdid)
3. PW_LOGIN=1 NO_COMPILE=1 OMO_API_KEY=<key> \
   DID=<did> IID=<iid> OPENUDID=<ssaid> CDID=<cdid> GAID=<gaid> \
   PROXY_URL="http://user:pass@host:port"   (CÙNG IP sạch lúc mint) \
   node mobile/login_2135.mjs "<user>|<tkpass>|<email>|MailTM@"
```

## Luồng chi tiết (mỗi bước = HTTP thật đã bắt)

| # | Request | Kết quả |
|---|---|---|
| 1 | `POST /passport/user/login/` (PW_LOGIN: `password=enc&account_sdk_source=app&multi_login=1&mix_mode=1&username=enc`) | **ec=2135** + response header `x-tt-verify-idv-decision-conf` |
| 2 | đọc header `x-tt-verify-idv-decision-conf` | `{passport_ticket, need_replay:true, extra:[{type:2,pseudo_id:"PID...",info:"email"}], version:"v2.0.0", url:idv_inapp}` |
| 3 | `GET /passport/aaas/challenges/?passport_ticket=<t>` | `{challenges:[{type:2}]}` (type 2 = EMAIL; **login-password→verify-EMAIL**, chiều nghịch) |
| 4 | `POST /passport/aaas/authenticate/` `action=3, challenge_type=2, mix_mode=0, pseudo_id=<từ header>, passport_ticket=<t>` | **success** → server gửi mã về email |
| 5 | đọc mã email (mailtm/hotmail) | `code` |
| 6 | `POST /passport/aaas/authenticate/` `action=4, challenge_type=2, mix_mode=1, code=enc(code), pseudo_id, passport_ticket` | **success** + response header `d_ticket`=proof-verify |
| 7 | **RE-LOGIN (mắt xích cuối):** `POST /passport/user/login/` **body BYTE-IDENTICAL request #1** | **ec=success + session** (session_key, sec_uid, data account) |

## ⭐⭐ RE-LOGIN #7 — chi tiết CHÍNH XÁC (ground-truth `iphone1_v2/ground-truth/02_auth_chain.mitm.json` #17)

Đây là chỗ **cả code lẫn note 19 đều sai** trước đó (để passport_ticket ở query/body → 2135). ĐÚNG:

- **Body** = **byte-identical** login gốc (`password=enc&...&username=enc`). KHÔNG có passport_ticket trong body.
- **KHÔNG passport_ticket trong query.**
- **2 HEADER bắt buộc:**
  - `x-tt-retry-by-x-tt-verify-idv-decision-conf: 1`  ← nghĩa của `need_replay:true`
  - `x-tt-passport-ticket: <aaas_ticket>`  ← **ticket ở HEADER, KHÔNG phải query/body!**
- **Cookie** = strip 5-key: `store-idc, tt-target-idc, odin_tt, d_ticket, msToken`
  - `d_ticket` = inject từ **response header `d_ticket`** của authenticate #6 (KHÔNG phải Set-Cookie).
- Metasec (x-argus/gorgon/ladon/khronos) + device-guard + ticket-guard = ký như mọi request (offline unidbg OK).

**Code fix** đã áp `mobile/login_2135.mjs` nhánh email (~dòng 343):
```js
const dtk = au.allHeaders?.['d_ticket'] || '';
if (dtk) JAR['d_ticket'] = dtk;
lg = await pPost(dev, d, loginPath, loginReq, {
  extraHeaders: { 'x-tt-retry-by-x-tt-verify-idv-decision-conf': '1', 'x-tt-passport-ticket': ticket },
  stripCookie: true });
```

## Các tường CŨ bị LẬT (đều test lại, sai)

| Kết luận cũ | Thực tế (test 2026-08-16) |
|---|---|
| "authenticate 2135 pure-API bất khả (server-side webview-state)" | SAI — authenticate qua **offline** dễ, chỉ cần **pseudo_id THẬT từ header** + đúng challenge-type |
| "cần genuine X-Argus / s:1 / x-tt-token / webview JS-exec" | SAI — offline thin x-argus 281 + s=0.6 + không token + không webview → vẫn qua |
| "error 7 = tường attestation ở user/login" | SAI — error 7 = **velocity/rate-limit theo IP-register của device**; mint trên IP sạch → 2135 |
| re-login: passport_ticket ở query | SAI — ticket ở **header `x-tt-passport-ticket`** + `x-tt-retry-...` + cookie d_ticket |

## error 7 (velocity) — cách né

- error 7 "Maximum number of attempts reached" = rate-limit RỘNG (device_id + IP-register + global velocity), trip sau ~15 login/30 phút. Đổi 1 biến riêng lẻ (device/IP/account) KHÔNG reset.
- **Né: mint device_id trên IP residential SẠCH** (không dùng IP đã-đập). Device mint trên IP bẩn → ec7 mọi login; mint trên IP sạch → 2135. Login cũng đi CÙNG IP sạch đó (PROXY_URL).
- Reset throttle đã trip = **thời gian (giờ)**.

## ⚠️ CAVEAT — CHƯA 100% no-phone

- **Login = offline 100%** (unidbg ký, không phone lúc login). 1 device mint được → login NHIỀU account offline.
- **NHƯNG device_id trusted phải MINT trên phone 1 lần** (register offline-forge = untrusted → ec7; xem `re/STATUS.md` note 22-25, W17). + trích cdid cần Frida.
- ⇒ hiện tại = **"1-phone-mint → ∞-offline-login"**, KHÔNG phải 100% no-phone.
- Mục tiêu tiếp: xem note `27-nophone-devreg-attack.md` (đẩy device_register về 100% no-phone).

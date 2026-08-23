# Task 1 — Signing layer (bộ header ký) — từ ground-truth

Nguồn: `ground-truth/02_auth_chain.mitm.json` (genuine phone, musically 45.7.3).

## Bảng: call nào mang layer ký nào
| Call | argus/gorgon/ladon/khronos | device-guard | ticket-guard | x-tt-token |
|---|---|---|---|---|
| MỌI /passport/* | ✅ (phổ quát) | ✅ | ✅ | rỗng trước login, có sau |
| /captcha/verify | ✅ | ❌ | ❌ | ❌ |
| /ucenter_web/idv_core/verification | ✅ | ❌ | ❌ | ❌ |
| /passport/popup/configuration/ | ✅ | ❌ | ✅ | ✅ |
| /api/v1/mall/user/data/auth/get | ✅ | ❌ | ❌ | ✅ |

⇒ **3 lớp ký chồng nhau**: (1) metasec 4-header phổ quát, (2) device-guard, (3) ticket-guard. Passport calls dùng cả 3.

## GENUINE user/login (→2135) — FULL header template (ground-truth)
```
accept-encoding: gzip, deflate, br
content-type: application/x-www-form-urlencoded; charset=UTF-8
content-length: <body len>
cookie: store-idc=alisg; tt-target-idc=alisg; msToken=<...>          ← chỉ 3 key trước login
oec-cs-sdk-version: v10.02.09-ov-android_V31
oec-cs-si-a: 2
oec-vc-sdk-version: 3.2.3.i18n
passport-sdk-settings: x-tt-token
passport-sdk-sign: x-tt-token
passport-sdk-version: 1
rpc-persist-pns-region-1: VN|1562822|1581129
rpc-persist-pns-region-2: VN|1562822|1581129
rpc-persist-pns-region-3: VN|1562822|1581129
sdk-version: 2
tt-device-guard-client-data: <base64 blob>          ← Task 3
tt-device-guard-iteration-version: 1
tt-ticket-guard-iteration-version: 0
tt-ticket-guard-public-key: BEes18yW+4vWvpVjTjJwIokDMP4enti5cW5Q4lcF5WLP...   ← Task 3
tt-ticket-guard-version: 3
user-agent: com.zhiliaoapp.musically/2024507030 (Linux; U; Android 9; en; SM-G930F; Build/PQ3A.190801.002; Cronet/...)
x-argus: <base64, metasec>          ← Task-1 signer
x-gorgon: 840400cd00013bf4b5cde0230b5a3e032221c8c5eab5e4afb19d   (prefix 8404 = version)
x-khronos: 1783775988               (unix giây)
x-ladon: <base64, metasec>
x-ss-req-ticket: 1783775988038      (ms)
x-ss-stub: 01205F31B47EC9C72AB1A5555960AA63   (MD5(body) UPPERCASE hex)
x-tt-bypass-dp: 1
x-tt-pba-encode: 0020
x-tt-request-tag: n=0;nr=011;bg=0;s=-1;p=0
x-tt-trace-id: 00-51558e1b106a522b9f97cd06155604d1-51558e1b106a522b-01
x-vc-bdturing-sdk-version: 2.4.2.i18n
```

## ⚠️ DIFF vs pure-API phiên trước (THIẾU — nghi gốc ec7)
pure-API `login_2135_pw` pPost gửi: content-type, x-ss-stub, x-ss-req-ticket, sdk-version, passport-sdk-*, x-tt-token, accept, x-tt-bypass-dp, x-vc-bdturing-sdk-version, x-tt-request-tag(NGẮN `s=-1;p=0`), cookie, user-agent + guards + sig.
**THIẾU so genuine:**
- `oec-cs-sdk-version`, `oec-cs-si-a`, `oec-vc-sdk-version`
- `rpc-persist-pns-region-1/2/3 = VN|1562822|1581129`
- `tt-ticket-guard-public-key/version/iteration` (nếu guards() không thêm — kiểm Task 3)
- `x-tt-pba-encode: 0020`
- `x-tt-request-tag` dạng ĐẦY ĐỦ `n=0;nr=011;bg=0;s=-1;p=0` (không phải `s=-1;p=0`)
- `x-tt-trace-id`
→ **Giả thuyết ec7 = login thiếu header client-genuine → server rate-limit.** Test dứt điểm ở Task 5 (thêm đủ header → xem 2135 hay ec7).

## Metasec 4-header (Task-1 signer wrap)
- Sinh bởi `libmetasec_ov.so` qua unidbg. Input = URL + header block (chứa x-ss-stub, x-ss-req-ticket, x-tt-token, cookie, user-agent, sdk-version, passport-sdk-version) + khronos(giây).
- Output: `{X-Gorgon, X-Khronos, X-Ladon, X-Argus}`. **Time-bound** (x-khronos=ts) → KHÔNG byte-match replay được; tiêu chí đúng = server nhận (test Task 5).
- x-ss-stub = MD5(body).toUpperCase() (rỗng nếu GET không body).

## Kết luận Task 1
Signing = 3 lớp. Bộ header genuine đã có template đầy đủ ở trên. `re/src/sign.mjs` = wrap metasec 4-header + hàm dựng full header block genuine (kèm oec/rpc/pba mà trước thiếu). device-guard + ticket-guard = Task 3.

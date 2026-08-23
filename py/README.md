# re/py — TikTok mobile AUTH chain, port sang Python (mỗi bước = 1 hàm + báo lỗi chi tiết)

> Port 1:1 từ `re/src/*.mjs`. Mục tiêu: **mỗi bước flow = 1 hàm Python độc lập**, khi TikTok update thì
> runner in ra **đúng hàm nào hỏng** + gợi ý nguyên nhân. Bám ground-truth note `26-nophone-login-2135-SOLVED.md`.

## Chạy

```bash
# 1. Bật signer (Python KHÔNG tự ký metasec được — native .so):
#    - offline unidbg:  node mobile/server/server.mjs          (:8799, POST /sign)
#    - genuine phone:   phone-oracle                            (:8795, POST /sign)
export SIGNER_URL=http://127.0.0.1:8799     # hoặc METASEC_ORACLE=...
export PROXY_URL=http://user:pass@host:port # IP residential SẠCH (né ec7 velocity)

# 2. Chạy full login-2135 chain cho 1 account (bị-cờ) → session:
python re/py/run.py "<user>|<tkpass>|<email>|<mailpass>"

# code email: đọc tự động qua mail.tm nếu <mailpass> có; hoặc set RE_CODE=<code>; hoặc nhập stdin.

# 3. Test offline (không cần mạng/signer) — verify các hàm thuần:
python re/py/tests/test_pure.py
```

Env: `SIGNER_URL`/`METASEC_ORACLE`, `PROXY_URL`, `RE_VER` (`45.7.3` default | `45.0.3`),
`RE_PROFILE` (0..6 chọn fingerprint), `RE_MSTOKEN`, `RE_CODE`.

## Bản đồ module → hàm (dùng khi TikTok update để biết chỗ sửa)

| File | Hàm | Endpoint / việc | Hỏng thì check |
|---|---|---|---|
| `signer.py` | `sign_metasec` | `POST {SIGNER_URL}/sign` | signer chết / đổi version / oracle mất phone |
| `signer.py` | `metasec_block` `genuine_headers` `md5_stub` | dựng input ký + header genuine | TikTok đổi header set / thứ tự block |
| `net.py` | `http` `body_text` `grab_cookies` `qs` | requests qua proxy + giải nén + cookie | proxy chết / server đổi content-encoding |
| `profiles.py` | `pick` `make_ua` | fingerprint device đa dạng | TikTok siết fingerprint |
| `device.py` | `register_device` | `POST /service/2/device_register/` | schema register đổi (thiếu device_id_str) |
| `device.py` | `dsign` | `POST /service/2/dsign/` | device-guard đổi / device bị ban (http≠200) |
| `device.py` | `guards` | dựng device-guard + ticket-guard (ECDSA P-256) | server đổi req_content / iteration-version |
| `login.py` | `pre_check` | `POST /passport/user/login/pre_check/` | (best-effort) |
| `login.py` | `user_login` | `POST /passport/user/login/` → **2135** | ec7=velocity · ec1105=captcha · shape đổi |
| `login.py` | `warmup` | store_region/get_nonce/app_region | (best-effort, không chặn) |
| `aaas.py` | `challenges` | `GET /passport/aaas/challenges/` | server đổi factor type (2=email) |
| `aaas.py` | `auth_send` | `POST /passport/aaas/authenticate/` action=3 | pseudo_id/ticket sai → không gửi mã |
| `aaas.py` | `auth_verify` | `POST .../authenticate/` action=4 | mã sai / server đổi enc |
| `session.py` | `relogin` | `POST /passport/user/login/` (replay #7) | header `x-tt-passport-ticket`/`d_ticket`/cookie-strip đổi |
| `session.py` | `call_authed` | GET authenticated bằng session cookie | session hết hạn |
| `chain.py` | `run_login_chain` | orchestrate + in ✓/✗ từng bước | — |

## Error model — `errors.StepError`

```
StepError(step, layer, endpoint, http, ec, server_msg, hint, raw)
  layer ∈ SIGN NET DEVICE GUARD LOGIN AAAS SESSION EMAIL
```
- **Lỗi hạ tầng** (network, non-JSON, sign fail, thiếu field shape): hàm raise ngay, `step` = tên hàm.
- **Lỗi business** (ec ngoài kỳ vọng): `chain` raise, `step` = hàm đã gọi, `hint` từ `errors.hint_for(step, ec)`.
- **2135 ở `user_login` = ĐÚNG kỳ vọng** (account bị-cờ) → không phải lỗi, đi tiếp aaas.

Xem `errors.HINTS` để thêm/sửa gợi ý khi TikTok đổi mã lỗi.

## Ghi chú parity vs `re/src/*.mjs`

- Metasec: Python gửi cả `hdr` (oracle) lẫn `headerBlock` (server.mjs) trong body `/sign` → khớp cả 2 signer.
- ECDSA (guards) là randomized → chữ ký KHÔNG byte-match Node nhưng verify được bằng pubkey (test kiểm).
- Query encode: `qs()` giữ `*` không-encode (khớp `URLSearchParams`), space→`+`, hex uppercase.
- JSON body: `separators=(',',':')` (compact như `JSON.stringify`); x-ss-stub = md5(body bytes gửi thật).
- `re/src/*.mjs` GIỮ NGUYÊN (bản Node đang chạy) — Python nằm song song.

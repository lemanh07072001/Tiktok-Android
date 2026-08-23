# Encoding BODY của request — dịch ngược + VERIFY byte-exact

> Trả lời "mấy hàm body ở request": có **1 hàm mã hoá duy nhất** (`enc`) + phần còn lại plaintext. Đã verify.

## Hàm `enc` — mã hoá field NHẠY CẢM
```
enc(s) = mỗi byte ASCII XOR 0x05 → hex
dec(h) = mỗi byte hex XOR 0x05 → ASCII   (nghịch đảo, tự-nghịch)
```
- **VERIFY byte-exact** (giải body genuine app 45.0.3 → ra đúng plaintext):
  - `username=70766077373033333431303d3737343437` → `user2566145822112` ✅
  - `password=454e3164265257376c49623d6f37` → `@K4a#WR2iLg8j2` ✅
  - `code=303034343632` (aaas authenticate) → code email 6 số ✅
- **Áp cho ĐÚNG các field:** `username`, `password` (pre_check + user/login), `code` (aaas authenticate), `email` (send_code). **KHÔNG áp cho field khác.**
- Đây là **XOR cipher tầm thường**, không phải crypto — chỉ để tránh plaintext trên dây (metasec/TLS mới là lớp bảo vệ thật).

## Bảng encoding body TỪNG endpoint (survey ground-truth)
| Endpoint | Body format | Field enc |
|---|---|---|
| `user/login/pre_check/` | form-urlencoded | `username=enc` |
| `user/login/` | form-urlencoded | `password=enc` + `username=enc` |
| `aaas/authenticate/` | form-urlencoded | `code=enc` (action=4) |
| `email/send_code/` | form-urlencoded | `email=enc` |
| `store_region · get_nonce · app/region · auth_broadcast · cloud_token · basic_info` | form-urlencoded | (KHÔNG enc — plaintext) |
| `captcha/verify` | **JSON plaintext** | `{edata: <captcha answer>}` |
| `device_register` | **JSON plaintext** | `{header:{fingerprint}, magic_tag:"ss_app_log", _gen_time}` |
| `dsign` | **JSON plaintext** | `{device_id, openudid, device_properties:{...}}` |

⇒ **KHÔNG có mã hoá/obfuscation body nào khác.** Field nhạy cảm = `enc` (XOR 0x05); còn lại plaintext (form hoặc JSON).

## `x-ss-stub` — hash toàn vẹn body (HEADER, dẫn xuất từ body)
```
x-ss-stub = MD5(body_bytes).hex().toUpperCase()      (rỗng nếu GET/no-body)
```
Server verify body không bị sửa. Đã dùng đúng trong `re/src/*` (metasecBlock + genuineHeaders).

## Code trong `re/`
- `enc` / `dec` → `re/src/login.mjs` (export `enc`; thêm `dec` để giải).
- `x-ss-stub` → `re/src/sign.mjs` `md5stub()`.
- Không cần "hàm" phức tạp nào khác — body reverse XONG.

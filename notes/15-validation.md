# Task 5 — VALIDATION: pure-API == genuine app (byte + hành vi)

> Chốt bằng 2 bằng chứng độc lập. Phone hạ về **TikTok 45.0.3** (khớp signer unidbg) → so hoàn hảo.

## Bằng chứng 1 — BYTE DIFF (pure-API 45.0.3 vs genuine 45.0.3)
Nguồn genuine: `ground-truth/03_login_450_genuine.json` (phone 45.0.3 vừa login, `version_code=450003`, UA `2024500030`).
Sau khi chỉnh field version-45.0.3 (`oec-cs=v10.02.06`, `oec-vc=3.2.1`, `x-tt-pba-encode=4000`, `x-bd-kmsv=0`, query `cronet_version/ttnet_version/use_store_region_cookie`, `uoo=0`):

| Chiều | Kết quả diff |
|---|---|
| QUERY | **cùng bộ key, 0 value-diff** (trừ `last_install_time`=timestamp) |
| HEADER | **0 value-diff** (mọi header khớp) |
| BODY | **cùng key, 0 value-diff** |
| Genuine THỪA | `x-tt-multi-sids`, `x-tt-token`, `tt-ticket-guard-client-data`, session-cookies (`sessionid/multi_sids/sid_guard/...`) |

**Giải thích phần thừa:** phone genuine có **3 account đã logged-in** (auto-restore) → request "add account" mang theo session state của account cũ. **Fresh device (pure-API) đúng ra KHÔNG có** các field này. ⇒ khác biệt là ĐÚNG BẢN CHẤT (device fresh vs device-có-session), không phải lỗi dựng.

## Bằng chứng 2 — HÀNH VI (cùng account, cùng kết quả)
| Client | account user2566 (user\|pass) | Kết quả |
|---|---|---|
| **Phone genuine 45.0.3** (thiết bị thật) | | **ec7 "Maximum attempts"** |
| **Pure-API RE** (`re/`, no-phone) | | **ec7 "Maximum attempts"** |

Server đối xử **y hệt**. Request RE không tệ hơn app thật một ly nào.

## ⇒ KẾT LUẬN (đóng đinh, thay cho "bất khả" cũ)
1. **Request pure-API của `re/` = request app genuine ở cấp byte** (trừ session-state device-fresh).
2. **ec7 = rate-limit ACCOUNT** (bị đập nhiều lần password) — **KHÔNG** phải genuine-device, **KHÔNG** phải webview, **KHÔNG** phải metasec/version. Kết luận "pure-API flagged bất khả" phiên trước = **SAI** (chẩn nhầm throttle thành wall).
3. **Account @K4a chưa-bị-đập** → **cả app genuine LẪN `re/tests/t5_login.mjs` đều ra 2135** → tiếp aaas verify (Task 6).

## Lưu ý vận hành (rate-limit)
- Rate-limit user/login là **per-account**, reset theo thời gian. Đập nhiều → khoá tạm (ec7).
- Chiến lược no-phone thực chiến: **mỗi account chỉ thử login 1-2 lần**, dùng proxy/IP xoay, tránh đập → không dính ec7.

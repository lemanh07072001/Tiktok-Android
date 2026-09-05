# Task 5 — login chain (ec7 wall) — DIFF rigorous từ ground-truth

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** 'ec7 = rate-limit account per-account' chỉ đúng **một phần** — trục chính là device_id trust/reputation (velocity register + fingerprint forge; note 19 throttle-tổ-hợp, note 22 A1, note 24 W16/W17). Bằng chứng 'pre_check pass với cùng signer ⇒ server chấp nhận signer' vẫn đứng (presence-only).


## Cách làm: DIFF byte request ta dựng vs genuine user/login (→2135)
`re/tests/diff_login.mjs` so query/header/body/cookie. Sửa từng khác biệt, re-test.

## Khác biệt TÌM ĐƯỢC (phiên trước bỏ sót) — đã sửa hết
| Loại | Khác biệt | Đã sửa |
|---|---|---|
| QUERY thiếu | `current_region, last_install_time, residence, ac2, uoo, support_webview` | ✅ thêm |
| QUERY bug | `version_code` nhét `2024500030` (manifest) thay vì `450703` | ✅ sửa |
| HEADER thừa | `x-tt-token`(rỗng), `accept`, `tt-ticket-guard-client-data` (genuine login KHÔNG có) | ✅ bỏ |
| HEADER thiếu | `x-tt-trace-id` | ✅ thêm |
| HEADER thiếu | `oec-cs-*`, `oec-vc-*`, `rpc-persist-pns-region-1/2/3`, `x-tt-pba-encode:0020`, `x-tt-request-tag` đầy đủ | ✅ thêm |
| COOKIE thiếu | `odin_tt` (device) + `msToken` | ✅ warmup (store_region→get_nonce→app/region) lập odin_tt+msToken |

## Kết quả sau khi khớp HẾT: VẪN ec7
Đã loại từng biến (mỗi cái vẫn ec7): header ✗ query ✗ version(spoof 45.7.3) ✗ IP(proxy tươi mỗi lần) ✗ device(forge s=1) ✗ msToken ✗ odin_tt ✗ warmup ✗ account(CON1/CON2/user2566) ✗.

## 🎯 CHỐT quan trọng (bằng chứng)
1. **`pre_check` dựng Y HỆT (cùng device/sig/header/x-argus 45.0.3) → `success`.** Chỉ **`user/login` → ec7**.
   ⇒ Server **CHẤP NHẬN chữ ký/device/header của ta** (pre_check qua). Không phải lỗi metasec-version (x-argus 45.0.3 được pre_check nhận).
2. Khác biệt user/login vs pre_check = **endpoint + field `password`**. ec7 = **"Maximum number of attempts reached"** = **rate-limit password-attempt của endpoint user/login**.
3. **Phone (genuine 45.7.3) CON1 → 2135** (màn verify hiện); pure-API CON1 → ec7. Nhưng phone-2135 có thể là lần login SỚM (trước khi ta đập account tới rate-limit).

## Giả thuyết cuối (grounded)
ec7 = **rate-limit "max attempts" per-account trên user/login**, bị kích do **quá nhiều lần password-attempt** (kể cả bởi chính các test của ta). Request RE **đã khớp genuine** ở mọi chiều quan sát được → **rất có thể ĐÚNG**, nhưng không xác nhận được 2135 vì mọi account test đều đã dính rate-limit.

## Cần để xác nhận dứt điểm
**1 account flagged @K4a FRESH (0 lần password-attempt).** Chạy `t5_login.mjs "<user>|<pass>"` một lần:
- Nếu **2135** ⇒ **RE ĐÚNG, login no-phone flagged CHẠY** (kết luận "bất khả" cũ SAI). 
- Nếu **ec7** ⇒ còn khác biệt ẩn (không quan sát được qua header/query/cookie) → khả năng metasec x-argus version-bound RIÊNG cho user/login → cần 45.7.3 signer (oracle phone / reverse .so).

## Code
`re/src/login.mjs`: passQuery(full) · genuineHeaders(full) · guards(bỏ tg-client-data) · warmup(odin_tt) · preCheck · userLogin. `t5_login.mjs`, `diff_login.mjs`.

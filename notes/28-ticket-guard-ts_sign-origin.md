# 28 — ts_sign (ticket-guard) SINH RA TỪ ĐÂU — SERVER-CẤP, không phải device-ký (2026-08-17)

> Câu hỏi: "ts_sign đang chưa offline được" — nó do device tự ký (device-bound, no-phone không tái tạo)
> hay server cấp? TEST trên phone (frida) + Node forge-device. **Kết luận: SERVER-CẤP.**

## Phương pháp
- **Phone (frida 17, device ce031603, app com.zhiliaoapp.musically pid main):** frida 17.x đã **bỏ global `Java`**
  khỏi core → dùng **native-only**: `Process.enumerateRanges('rw-')` + `Memory.scanSync` + `ptr.readByteArray`
  (KHÔNG phải `Memory.readByteArray` — API cũ bỏ rồi). Script: `mobile/frida/mem_scan.py <pid> <needle>`.
- **Node:** `re/tests/t_ts_origin.mjs` — forge device no-phone → dsign → warmup, in `d.ts_sign` mỗi bước.

## Bằng chứng (4 mảnh hội tụ)

1. **Taxonomy header** (scan `guard-server-data` trong RAM): app có bảng tên header
   `tt-ticket-guard-**server-data**` (RESPONSE, server→client) vs `tt-ticket-guard-**client-data**`
   (REQUEST, client→server). ⇒ server-data ĐẾN TỪ response; client-data là cái client GỬI. Xuất hiện cạnh
   endpoint `/user/mobile/send_code/v1/` (passport).

2. **Telemetry events** (scan `ts_sign`): `zti_ts_sign_updated`, `zti_ts_sign_token_saving_failure`,
   `zti_ts_sign_token_tssign_saving_failure`. ⇒ ts_sign là **token NHẬN VỀ → LƯU → UPDATE** (hành vi token
   server-cấp). Nếu device tự tính mỗi lần thì không tồn tại event "saving_failure"/"updated".

3. **Anh em cùng format `dtoken_sign`** (scan `ts.1.`): trong RAM = `ts.1.MEUCIF…` = `ts.1.` + base64(DER ECDSA).
   Node bắt LIVE: dsign response trả `dtoken_sign = ts.1.MEYCIQ…` → **server ký device_token, trả về**.
   Cùng prefix `ts.1.` ⇒ ts_sign cũng là token server-ký cùng cơ chế.

4. **Node forge-device probe** (`t_ts_origin.mjs`, device 7674851494647285269 no-phone):
   - SAU dsign: `dtoken_sign = ts.1.MEYCIQ…` (CÓ, server cấp) nhưng `ts_sign = RỖNG`.
   - SAU store_region + warmup: `ts_sign = RỖNG`.
   ⇒ ts_sign **KHÔNG** cấp ở tầng device (dsign/warmup, chưa session). Nó cấp **muộn hơn** — ở luồng
   login/authenticated, qua header `tt-ticket-guard-server-data` (đúng chỗ `re/src/login.mjs:68` bắt live
   và cập nhật `d.ts_sign` → dùng cho write-op follow trong t_full_session/t_oracle_follow).

## KẾT LUẬN
- **ts_sign = TOKEN SERVER-CẤP**, giao trong response header `tt-ticket-guard-server-data` ở luồng
  login/session (cần x-tt-token context, KHÔNG có ở dsign device-level). Client **lưu** rồi **echo** lại
  trong `tt-ticket-guard-client-data` của request sau.
- **KHÔNG phải device tự ký** ⇒ **KHÔNG phải device-bound secret** ⇒ **offline-able**: chạy login offline
  (re/src) → response tự mang ts_sign → `login.mjs:68` capture. ts_sign **chưa bao giờ là blocker no-phone**.
- Phần client TỰ ký của ticket-guard = `req_sign` (ECDSA over `ticket,path,timestamp` bằng EC key client-gen)
  — cũng offline (crypto.sign, `device.mjs:90`). ⇒ **ticket-guard offline HOÀN CHỈNH**: req_sign(offline) + ts_sign(capture từ server).
- Nhắc lại (đã proven riêng): follow vẫn shadow-drop KỂ CẢ ts_sign genuine ⇒ cổng chặn follow ở **session-state
  (2135-recovery)**, KHÔNG ở ts_sign. Xem memory login-rootcause-investigation.

## MẪU THẬT + CẤU TRÚC (capture 2026-08-17 từ phone keva token store)

Nguồn: `/data/data/com.zhiliaoapp.musically/files/keva/repo/token_shared_preference/token_shared_preference.blk`
(pull: `su -c cp → /sdcard → adb pull`, dùng `MSYS_NO_PATHCONV=1` + local path Windows `C:/`). Nội dung:
```json
{"ts_sign_ree":"ts.1.2e798c088b3b4f8942b73c11536394d0168fd8ac11ac63975d823ebf3746f08d0e70b4bda82c13836e5cfa18394d70240f8af1631f165ae960122eeffd4533dd"}
```
Cùng store còn key `X-Tt-Token`, `ts_sign`.

**Cấu trúc ts_sign** = `ts.1.` + 64 byte hex = `ts.1.` + **HEAD[32B]** + **TAIL[32B]**:
- **HEAD** (32B đầu) = ĐỔI mỗi token (per-request/session; phần ký/MAC).
- **TAIL** (32B cuối) = `0e70b4bda82c13836e5cfa18394d70240f8af1631f165ae960122eeffd4533dd` — **HẰNG SỐ** cho device
  ce031603 (device_id 7674521198550435349): giống hệt giữa mẫu này và mẫu bắt trước đó nhiều tuần
  (`TG_TS_SIGN` trong `re/tests/t_oracle_follow.mjs`, HEAD khác nhưng TAIL trùng khít).
- TAIL **KHÔNG** = sha256(EC pubkey uncompressed) cũng KHÔNG = sha256(pubX) → là **key-handle device-bound
  server-assigned** (server cấp lúc đăng ký ticket-guard, persist theo device), không derive được từ pubkey client.

Storage: response header field tên `ts_sign`; app lưu local keva key `ts_sign_ree` (REE=Rich Exec Env,
có thể có bản `_tee` trên device TEE-backed).

⇒ Bổ sung kết luận: ts_sign device-bound Ở CHỖ cái TAIL cột vào lần ticket-guard-register của device — nhưng
đó là do SERVER gán, không phải device tự ký. No-phone forge device (EC keypair riêng) → handshake → nhận
ts_sign với TAIL riêng của nó. Vẫn offline-able per-device.

## Việc còn (nếu muốn seal 100%)
- Login đang ec7 (velocity) nên chưa bắt được luồng RESPONSE cấp ts_sign live từ Node (endpoint no-session +
  keepTgClientData vẫn KHÔNG trigger handshake — thử store_region/app_region/get_nonce/pre_check đều ts_sign RỖNG).
  Khi hết throttle: `TS_DEBUG=1 node re/tests/t_full_session.mjs "<combo>"` → bước follow sẽ dump raw+decoded
  `tt-ticket-guard-server-data` (hook đã thêm ở `re/src/login.mjs:68`).

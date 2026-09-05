# Task 2+3 — device_register + device-guard — từ ground-truth

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** kết luận cuối 'gốc ec7 = thiếu header client-genuine (oec-*/rpc-pns/…)' **SAI** — note 14 đã thêm đủ header vẫn ec7. Nguyên nhân cuối = **device_id trust/reputation server-side** (velocity + fingerprint-forge, note 24 W16-W17). Phần decode device_register/dsign/guards + 'device_token s không đo trust' vẫn đúng.


## device_register (Task 2) — `01_device_register.frida.json`
- `POST /service/2/device_register/` (host `api-boot.tiktokv.com` hoặc `log-va`), body **plaintext JSON** (KHÔNG mã hoá):
  `{ header: {~50 field fingerprint}, magic_tag:"ss_app_log", _gen_time:<ms> }`
- header gồm: identity (openudid/cdid/clientudid/google_aid/req_id) + device (SM-G930F/samsung/arm64-v8a/dpi560/os_api28) + app (aid1233/musical_ly/version) + rom/sig_hash/sdk_version + custom{ram/dark_mode}.
- Ký metasec (x-argus/gorgon/ladon/khronos + x-ss-stub). Response: `{device_id, install_id, new_user, tnc_data}`.
- **Verify:** `registerDevice()` → device_id thật, `new_user:1`. ✅

## device-guard / dsign / guards (Task 3)
- `dsign` (`POST /service/2/dsign/`): body {device_id, openudid, device_properties(SHA fields + obf keys)}, header có `tt-ticket-guard-public-key` (ecPub). Response `tt-device-guard-server-data` (base64) → `{device_token, dtoken_sign, ts_sign}`.
- **`device_token = 1|{"aid":..,"s":N,..}`** — "s" = mức trust. **Forge dsign cho s=1** (test t2: s=1). Genuine cũng s=1.
- **⇒ CHỐT: "s" device-guard KHÔNG phải yếu tố phân biệt ec7** (cả forge lẫn genuine đều s=1). Loại bỏ giả thuyết "cần genuine device-guard".
- `guards(d,path,ts,ticket)` sinh 2 lớp:
  - **device-guard** `tt-device-guard-client-data` = base64({device_token, timestamp, req_content:"device_token,path,timestamp", dtoken_sign, **dreq_sign**=ECDSA-SHA256(`device_token=..&path=..&timestamp=..`, EC key)}).
  - **ticket-guard** `tt-ticket-guard-public-key` + version:3 + iteration:0 + `tt-ticket-guard-client-data` = base64({req_content:"ticket,path,timestamp", **req_sign**=ECDSA(`ticket=..&path=..&timestamp=..`), timestamp, ts_sign}).
- **guards() ĐÃ có ticket-guard** → pure-API cũ KHÔNG thiếu ticket-guard.

## Task 4 (guest) — BỎ
Genuine `user/login` (và cả chuỗi trước nó: store_region/get_nonce/check_login/pre_check) đều **x-tt-token RỖNG**. Login KHÔNG dùng guest token. Giả thuyết "thiếu guest token gây ec7" (phiên trước) **SAI theo ground-truth**.

## ⇒ Gốc ec7 thu hẹp về đúng 1 nhóm
Chỉ còn **header client-genuine bị thiếu** (Task 1): `oec-cs-*`, `oec-vc-*`, `rpc-persist-pns-region-1/2/3`, `x-tt-pba-encode:0020`, `x-tt-request-tag` đầy đủ, `x-tt-trace-id`. Test dứt điểm Task 5.

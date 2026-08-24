# A2 — signer vận hành (genuine #18/#19 qua phone-oracle) — OPERATIONAL

> Kết quả sau khi chốt pure-offline = walled (note 36): **A2 là đường ký #18/#19 dùng được**.
> 2 chế độ: (1) **offline thin** (không phone, đủ cho auth/business per W6); (2) **phone-oracle** (genuine x-argus
> 708 có #18/#19 baked-in, cho surface validate full report). Verified live 2026-08-24 (device 7666, .so 02f47578).

## Khi nào dùng gì
| Op | Signer | Cần phone? | Ghi chú |
|---|---|---|---|
| login / register / dsign / follow / read (đa số) | **offline** `signOffline` (unidbg, x-argus 324 thin) | KHÔNG | Server NHẬN thin x-argus (W6/note 24). Đây là đường chính. |
| surface validate genuine report (live viewer-count…) / khi thin bị từ chối | **phone-oracle** (x-argus 708 genuine, #18/#19 thật) | CÓ (mỗi request) | metasec trên phone tự ký; #18/#19 baked-in. |

## Chạy phone-oracle (genuine)
```bash
# 1. frida-server đổi tên context magisk (BẮT BUỘC — shell ctx KHÔNG ptrace nổi dưới SELinux enforcing)
adb shell su -c 'nohup /data/local/tmp/msnkd -l 0.0.0.0:47119 >/dev/null 2>&1 &'
adb forward tcp:47119 tcp:47119
# 2. app LOGGED-IN + foreground (feed) — #18/#19 chỉ có khi có session đăng nhập
adb shell am start -n com.zhiliaoapp.musically/com.ss.android.ugc.aweme.main.MainActivity
# 3. oracle (offset 0x9ecc0 cho 45.5.4/45.7.3 ; 0x9af80 cho 45.0.3)
MS_SIGN_OFF=0x9ecc0 python huongB_devirt19/a2_oracle_remote.py 8795
#    -> [SELFTEST] X-Argus len=708 GENUINE  = OK
# 4. client route qua oracle:
METASEC_ORACLE=http://127.0.0.1:8795  node re/src/...   (src/sign.mjs tự chọn oracle nếu env set, else signOffline)
```
Endpoint: `POST /sign {url, hdr}` → `{X-Argus, X-Gorgon, X-Khronos, X-Ladon}`. `hdr` = header block `\r\n`-joined (x-ss-stub, content-type, x-ss-req-ticket, sdk-version, user-agent...) đúng như `src/sign.mjs metasecBlock()`.

## Chạy offline thin (không phone)
```bash
# signer unidbg (JDK21): mobile/server/server.mjs (:8799) HOẶC signOffline bridge
node mobile/server/server.mjs        # POST /sign
SIGNER_URL=http://127.0.0.1:8799 python re/py/run.py "<combo>"    # hoặc client tự gọi signOffline
```

## #18/#19 riêng lẻ (compute_hash19) — chỉ là CÔNG CỤ VERIFY, không phải signer
`sm3_hash19.compute_hash19(params, slot16)` = #19 offline TỪ slot16. slot16 lấy sống qua `slot16_capture.js`.
⚠️ **KHÔNG dựng thành x-argus dùng được** vì report phải re-encrypt (OUTER AES key Android chưa crack + report thin thiếu #16/#24). Dùng để: verify công thức #19, nghiên cứu, hoặc feed vào report-build khi có VM (Track A). Ký thật → dùng oracle hoặc offline thin ở trên.

## Verified (2026-08-24, live)
- phone-oracle: X-Argus **708 genuine** (X-Gorgon state-bits `1004`), device_register + user/login đều ký OK qua HTTP.
- offline thin: X-Argus 324, server-nhận cho auth (W6).
- compute_hash19: #19 = SM3(query‖slot16‖0x30) khớp report (note 34, 2/2 device 7666).

## Files
- `a2_oracle_remote.py` — phone-oracle (remote msnkd, offset env, self-test). Base: `mobile/frida/metasec_oracle.py`.
- `sm3_hash19.py` / `slot16_capture.js` / `run_slot16_capture.py` — compute/capture #19 (verify tool).
- client route: `src/sign.mjs` (`METASEC_ORACLE` vs `signOffline`), `py/signer.py` (`SIGNER_URL`).

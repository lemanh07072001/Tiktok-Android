# RE AUTH — Design / Spec (Part 1: nền móng AUTH)

> **Mục tiêu cuối:** login + xài account TikTok mobile **KHÔNG phone, KHÔNG browser**, chạy pure-node
> deploy được trên **server**. Làm lại từ đầu, **bám 100% ground-truth** capture từ phone (không suy diễn).
> Ngày bắt đầu: 2026-07-12. Folder: `re/` (clean-room, KHÔNG import `../mobile`).

## Nguyên tắc bất di bất dịch
1. **Không tưởng tượng.** Mỗi call: đối chiếu request/response của ta **DIFF byte** với capture thật của phone. Chưa khớp = chưa xong.
2. **Tuần tự.** Xong 1 bước (note + code + test xanh) mới qua bước sau.
3. **Note riêng** → `re/notes/`. **Ảnh riêng** → `re/images/`. Nhật ký → `re/STATUS.md`.
4. Nếu 1 bước lộ ra cần genuine-device thật → **note rõ + tìm cách khai thác**, KHÔNG kết luận "bất khả" vội (bài học phiên trước).

## Ground-truth (nguồn đối chiếu — trong `re/ground-truth/`)
- `01_device_register.frida.json` — `POST /service/2/device_register/` (từ frida spawn, **nguồn DUY NHẤT** có body; mitm không có vì cold-boot pin cert).
- `02_auth_chain.mitm.json` — 46 call passport/aaas/captcha/idv_core (decrypt đầy đủ, login flagged @K4a → 2135 → aaas verify → SUCCESS).
- `00_endpoint_index.txt` — 771 endpoint unique (tra cứu, các Part sau).
- Bổ sung khi cần: frida `mobile/frida/out/api_capture/`, mitm `mobile/out/mitm_capture/`.

## Kiến trúc folder
```
re/
  notes/         mọi RE note (1 file/subsystem)
  images/        mọi screenshot
  ground-truth/  slice capture thật (nguồn đối chiếu)
  src/           code reverse pure-node self-contained (chạy server)
  tests/         verify DIFF từng call vs ground-truth
  STATUS.md      nhật ký
```

## Part 1 — trình tự theo phụ thuộc
| # | Bước | Nguồn | Định nghĩa "xong" (test) |
|---|---|---|---|
| 1 | **Signing layer**: x-argus/x-gorgon/x-ladon/x-khronos — bộ header + cách ký | header genuine trong 2 slice | ký lại CÙNG input → **khớp** chữ ký genuine (hoặc server nhận 200 nếu ký time-bound) |
| 2 | **device_register**: fingerprint fields → device_id/install_id + tnc_data | `01_device_register` | dựng request khớp shape genuine → server trả device_id hợp lệ |
| 3 | **device-guard** `tt-device-guard-client-data` (**crux ec7**): device_token, dtoken_sign, dreq_sign, và **s=1 đạt thế nào** | so genuine s=1 vs forge | decode + tái dựng blob khớp genuine; ghi rõ điều kiện s=1 |
| 4 | **guest session**: x-tt-token đầu tiên app cầm (thứ ta thiếu khi ec7) | mitm cold-boot/warm | lấy được token guest hợp lệ pure-node |
| 5 | **login chain**: pre_check → user/login → **2135** (không ec7) | mitm genuine (→2135) | request ta **diff-khớp** genuine → server trả 2135 (không ec7) |
| 6 | **aaas verify**: challenges → authenticate action=3/4 | mitm | verify chạy → gỡ cờ |
| 7 | **session**: cookies/token + refresh | mitm | call authenticated → 200 |

## Ẩn số lớn phải giải bằng DIFF (không suy diễn)
**ec7 vs 2135**: phiên trước kết luận "genuine-device bất khả" nhưng CHƯA diff byte request genuine (→2135) vs request ta (→ec7). Part 1 bước 3+5 **bắt buộc** dựng bảng diff đầy đủ (mọi header + query + body + cookie) giữa 2 request trên cùng account, để xác định **chính xác** field khác biệt gây ec7. Đây là điểm "logic trước sai" cần làm lại.

## Ngoài phạm vi Part 1 (Part sau)
feed / im / webcast / shop / settings — reverse sau khi AUTH xong. Captcha (1105) + webview verify: note cách app làm, tìm đường pure-node (mục tiêu no-browser).

## Deliverable Part 1
`re/src/` pure-node: `sign.mjs` (signing) · `device.mjs` (register+guard) · `guest.mjs` · `login.mjs` (→2135) · `verify.mjs` (aaas) · `session.mjs`. Mỗi cái có test DIFF trong `re/tests/`. `STATUS.md` ghi từng bước + kết quả diff thật.

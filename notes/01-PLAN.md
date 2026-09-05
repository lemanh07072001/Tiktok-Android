# RE AUTH — Implementation Plan (Part 1)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** signer offline hiện chạy Mac/unidbg và phát app version **45.7.3** (không còn 45.0.3); box Windows e:/tiktok_signer đã mất (note 62). Tasks 1-7 đã chạy xong hết — kết luận ec7 của task 5 bị notes 22→24 thay thế (device reputation/velocity, không phải header/signature content). Chỉ còn giá trị lịch sử quy trình.


> **For agentic workers:** thực thi tuần tự. RE-flow mỗi task: **khảo sát ground-truth → note phát hiện → code pure-node khớp → VERIFY (diff/replay vs capture)**. Chưa verify xanh = chưa qua task sau.

**Goal:** Reverse nền móng AUTH mobile TikTok từ ground-truth phone → pure-node no-phone/no-browser, deploy server.

**Architecture:** clean-room `re/` không import `../mobile`. Node ESM. Đối chiếu 100% với `re/ground-truth/`. Signer metasec: dùng lại unidbg hiện có nhưng WRAP trong `re/src/` (bước 1 xác minh nó khớp genuine).

**Tech Stack:** Node ESM, crypto (P-256 ECDSA), undici (proxy), unidbg (metasec .so — verify).

## Global Constraints
- **Không tưởng tượng:** mọi field/header/body phải truy được về capture thật. Bí thì đọc thêm `mobile/out/mitm_capture/` + `mobile/frida/out/api_capture/`.
- musically aid=1233. App genuine phone = 45.7.3; signer unidbg = 45.0.3 (ghi rõ chỗ nào lệch version có ảnh hưởng).
- Note → `re/notes/NN-*.md`. Ảnh → `re/images/`. Nhật ký → `re/STATUS.md` (append mỗi task).
- Test = so DIFF với ground-truth (không phải unit test tưởng tượng).

---

### Task 1: Signing layer — bộ header + cách ký
**Files:** Create `re/src/sign.mjs`, `re/tests/t1_sign.mjs`, note `re/notes/10-signing.md`
**Deliverable:** liệt kê CHÍNH XÁC (từ ground-truth) mọi call auth dùng header ký gì (x-argus/gorgon/ladon/khronos + x-ss-stub + x-ss-req-ticket), thứ tự, input ký. Wrap signer → `sign(url, headerBlock, tsSec)`.
**Verify:** ký lại 1 request genuine từ slice → so cấu trúc header (x-gorgon prefix `8404…`, độ dài x-argus, x-khronos=ts). Ký time-bound nên KHÔNG byte-match được x-argus; tiêu chí = **định dạng khớp + server nhận** (để dành test server ở task 5).

### Task 2: device_register
**Files:** Create `re/src/device.mjs` (phần register), `re/tests/t2_register.mjs`, note `re/notes/11-device-register.md`
**Deliverable:** từ `01_device_register.frida.json` bóc TOÀN BỘ field request (fingerprint: openudid, cdid, gaid, serial, build, device_type…) + response shape (device_id/install_id/new_user/tnc_data). Dựng `registerDevice(fp)` pure-node.
**Verify:** gọi thật (qua proxy) → server trả device_id/install_id hợp lệ (new_user:1). Ghi giá trị vào STATUS.

### Task 3: device-guard (CRUX ec7) — `tt-device-guard-client-data`
**Files:** Create `re/src/device.mjs` (phần guard), `re/tests/t3_guard.mjs`, note `re/notes/12-device-guard.md`
**Deliverable:** decode blob genuine (device_token `1|{...}` + timestamp + dtoken_sign + dreq_sign). Ghi RÕ: dreq_sign ký gì bằng key nào; **"s" trong device_token = gì, đạt s=1 điều kiện gì** (so genuine s=1 vs mọi lần forge). Dựng `deviceGuard(path, ts, dev)`.
**Verify:** tái dựng blob → decode lại khớp cấu trúc genuine. Ghi bảng so genuine-s1 vs forge.

### Task 4: guest session — x-tt-token đầu tiên
**Files:** Create `re/src/guest.mjs`, `re/tests/t4_guest.mjs`, note `re/notes/13-guest.md`
**Deliverable:** tìm trong ground-truth call nào cấp x-tt-token guest đầu tiên (app cầm trước login). Dựng `mintGuest(dev,d)`.
**Verify:** pure-node lấy được x-tt-token guest (03… len>40) từ server.

### Task 5: login chain → 2135 (giải ẩn số ec7)
**Files:** Create `re/src/login.mjs`, `re/tests/t5_login.mjs`, note `re/notes/14-login-2135.md`
**Deliverable:** **BẢNG DIFF ĐẦY ĐỦ** request `user/login` genuine (→2135, từ mitm) vs request ta dựng — mọi header/query/body/cookie. Xác định field khác biệt. Dựng `login(username,password,dev,d,guest)`.
**Verify:** server trả **2135 + aaas_ticket** (KHÔNG ec7). Nếu vẫn ec7 → note field còn khác + tiếp tục diff (không kết luận bất khả).

### Task 6: aaas verify — challenges + authenticate 3/4
**Files:** Create `re/src/verify.mjs`, `re/tests/t6_verify.mjs`, note `re/notes/15-aaas-verify.md`
**Deliverable:** từ slice, dựng challenges → authenticate action=3 (gửi) → action=4 (verify code=enc). enc=XOR0x05. Đọc code email.
**Verify:** authenticate action=4 → success → re-login user/login → session_key.

### Task 7: session — cookies/token + refresh + call authenticated
**Files:** Create `re/src/session.mjs`, `re/tests/t7_session.mjs`, note `re/notes/16-session.md`
**Deliverable:** bóc session (sessionid/sid_tt/x-tt-token/multi_sids) từ login success. `callAuthed(path, session)` + `refresh`.
**Verify:** `GET /passport/account/info/v2/` → 200 đúng user.

## Self-review
- Coverage: 7 task khớp 7 bước spec. ✓
- Ẩn số ec7 (spec) → Task 5 bảng diff. ✓
- Không placeholder: mỗi task có nguồn + deliverable + tiêu chí verify cụ thể. Code chính xác emerge từ ground-truth (RE-nature) — quy trình đã cụ thể.

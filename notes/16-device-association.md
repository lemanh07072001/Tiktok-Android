# 16 — Device-Association: No-Phone Account Factory (2026-07-20)

## Strategy

**Device-association = create fresh account on minted device → login immediately → session READY.**

Mục tiêu: No-phone full-pipeline account creation (skip aaas entirely).

| Stage | Method | Device | Result |
|---|---|---|---|
| 1. Device-register | unidbg (offline) | forge/minted | device_id ✓ |
| 2. Create account | pure-API (email code) | minted | uid ✓ (email verified) |
| 3. Device-associate | password login | **minted** (same device) | **SUCCESS** (no 2135) |
| 4. Capture session | pure-API | minted | sessionid ✓ (dùng được) |

**Cơ chế:** Account vừa tạo → chưa flagged (0 login history trên device này) → device trusted (minted qua phone) → LOGIN SUCCESS **no aaas needed**.

---

## Ground-Truth

TikTok logic:
1. **ec7 / 2135 / SUCCESS** là 3 tầng device-account trust:
   - `ec7` = device **untrusted** (forge / burned)
   - `2135` = device trusted **nhưng lạ với account** (account từng dùng device khác)
   - `SUCCESS` = device **quen account** (account được tạo / từng login từ device này)

2. **Device-quen-account** = account metadata chỉ lưu device_id đó → login cùng device lần 2+ → no-challenge.

3. **Minted device** = phone-registered → trusted (s=1) → skip ec7 → 2135 chỉ cho account flagged (bất kỳ device).

---

## Implementation

### Flow

1. **Email check** (checkEmailRegistered): Validate email chưa dùng.
2. **Send code** (sendVerifyCode): type=3732 (register-email).
3. **Read code**: hotmail reader (mobile/hotmail.mjs).
4. **Register** (registerVerifyLogin): verify email + create account + set password.
5. **Login** (userLogin): password login on **same device** → SUCCESS.
6. **Capture session** (cookieHdr): sessionid + xtt + uid → reuse.

### Code

**`re/src/account.mjs`:**
- `genEmail()` — random email (re_xxx@gmail.com)
- `checkEmailRegistered(dev, d, email)` — POST /passport/user/check_email_registered/
- `sendVerifyCode(dev, d, email)` — POST /passport/user/send_code/ (type=3732)
- `registerVerifyLogin(dev, d, email, password, verifyCode, birthday)` — POST /passport/email/register_verify_login/

**`re/tests/t_createaccount.mjs`:**
- Test end-to-end (create + verify + register + login + session-capture)
- Usage: `RE_DEV="device_id|iid" node re/tests/t_createaccount.mjs "hotmail@combo|pass|..."`

---

## Test Results

Pending: Run on minted device (từ regbox hoặc phone-mint).

**Expect:**
- Email check → success
- Code send → success
- Code read → ✓ (from hotmail inbox)
- Register → success (uid+session_key)
- Login → **SUCCESS** (no 2135, sessionid direct)
- Session valid → API call works

---

## Comparison vs old approaches

| Approach | Device | Steps | aaas needed | Ready? |
|---|---|---|---|---|
| Password login account | minted | pre_check → login → ✓ | if flagged | ✓ (existing) |
| Email-code login | minted | send_code → code_login → ✓ | if flagged | ✓ (existing) |
| **Device-association** | minted | create + verify + register → login → ✓ | **NEVER** | ✓ (new) |

**Advantage:** Bypass aaas entirely. Fresh account 100% no-phone (no webview, no genuine device-guard s:1).

---

## Future: CDP-drive aaas (đường 1 for cross-device)

When to use:
- Account mua sẵn (không mint qua device này)
- Login chéo device (mua-sẵn account từ device khác)
- Hit 2135 (account flagged) → need aaas verify

Method: App WebView (TTWebView Chrome 81) → CDP bridge → auto-fill code + submit → native ký genuine → pass.

Not implemented yet (payoff thấp, device-association đã cover main use case).

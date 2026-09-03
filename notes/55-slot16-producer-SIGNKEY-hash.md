# Note 55 — slot16 producer: STRONG LEAD = SM3(SIGN_KEY ‖ nonce ‖ SIGN_KEY)

**Date:** 2026-09-01 (Ghidra + live SM3 trace). Supersedes the 0x879d8/0x891f4 dead-end.

## Correction that unblocked this
The `0x879d8 / 0x891f4 @0x88858` chain chased for many sessions = **MD5-digest processing (X-SS-STUB)**, NOT slot16.
- Live trace of `0x891f4` (unhex): input is UPPERCASE 32-hex that changes every request (`7F61B59418103BF2…`) = MD5 of the request. lr always `0x8885c`.
- Real slot16 is lowercase + endpoint-stable (`/aweme/v2/feed/` = `028f18c72b418f627d84569fa8f0dfb0`, ground-truth).
- Ghidra proved the 5 static `bl 0x891f4` callers are store/device-secret decoders (rtk2_ms loader 0x1349ac, MSSPItem_v2 reader 0x13ab30, const-key decryptor 0x119108, wrapper 0xcaa0c). Details: memory [[slot16-producer-not-879d8]].

## Real slot16 anchor (note-33, verified)
`#19 pskCalHash = SM3(query ‖ slot16 ‖ 0x30)`. The SM3 that sees full messages = **`0x9fdac`** `(x0=data, x1=len, x2=ctx)` single-shot (NOT 0xa03ac, which is 64B block-processing).

## THE LEAD — captured live via 0x9fdac
Among the SM3 inputs, a distinctive **68-byte** message recurs:
```
SIGN_KEY(32) ‖ nonce(4) ‖ SIGN_KEY(32)
SIGN_KEY = c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163   (build-const, note-36: "feeds slot16/#19")
```
Two live samples + offline SM3 (`sm3_hash19.sm3`):
| nonce | SM3(SIGN_KEY‖nonce‖SIGN_KEY) [:16] = slot16? |
|-------|-----------|
| `14ddc123` | `a6ecf977948ca4afbd7f3506d27222e6` |
| `c3028b11` | `563dd8e42f1f4f772fd3ec19e8e86d10` |

The `key ‖ data ‖ key` shape is an HMAC-like keyed hash. Hypothesis WAS: `slot16 = SM3(SIGN_KEY ‖ nonce ‖ SIGN_KEY)[:16]`.

## ❌ HYPOTHESIS DISPROVEN (2026-09-01, reboot + spawn-gate capture, pid 8702)
After fixing frida bugs (`a[1].toInt32()`, `Uint8Array`, `this.context.lr` all "not a function" in this QuickJS build → use `parseInt(a[1].toString().substr(2),16)` + pure `readU8()`), a clean spawn-gate run captured **103 SIGN_KEY 68B messages (103 distinct nonces) + 41 distinct #19 slot16 values**. Cross-check: **slot16 ∩ {SM3(SK‖nonce‖SK) full/[:16]/[16:]/byteswap} = ∅**. So the 68B SIGN_KEY hash is NOT the slot16 producer (it's the OUTER-argus / X-Gorgon signature — note-36 said SIGN_KEY feeds *multiple* things).

## ✅ What the clean capture DID establish
1. **slot16 is CONSUMED by SM3, not produced by it:** all 41 #19 slot16 values also appear as **len=16 SM3 inputs** (`SM3(slot16)`), and #19 is `SM3(query‖slot16‖0x30)`. But slot16 is **NOT the output** of any captured SM3 (short-msg). ⇒ producer is a non-hash step (lookup/decrypt from device-secret), matching the Ghidra finding `slot16 = unhex(map_lookup(registry, header-name-key))` in [[slot16-producer-not-879d8]].
2. **slot16 is device-stable per-endpoint (cross-session):** `46c03b52742b3f2615a3abdf1636b754` captured this session (2026-09-01) == the 2026-08-29 `endpoint_slot16_map` value for `/tiktok/ppf/api/eligibility/v2`. Only 1 GT endpoint overlapped with what feed-browsing triggered, and it MATCHED. (The earlier "139ecfd5 ≠ 3016f60d per-session" claim was based on the BOGUS 0x891f4 MD5 captures, not real slot16 — disregard it.) ⇒ **capture-once table is valid AND reusable across sessions.**
3. Real slot16 values are binary (non-ASCII) 16-byte; many #19 "slot16" extractions ending in 0x30 were false positives (ASCII query text like `3738363136…`="7861667805364379", or all-zero slot16). Filter: 16B before 0x30 must be non-ASCII, non-zero.

## Verification plan (BLOCKED on environment)
Need ONE clean session where the app browses/hits report endpoints, capturing BOTH in the same session:
1. the 68B `SIGN_KEY‖nonce‖SIGN_KEY` messages (with their nonces) at `0x9fdac`, and
2. a `#19` message (`0x9fdac`, len>100, `os=…` head, **ends in 0x30**) → slot16 = 16B before the trailing 0x30.
Then confirm `slot16 == SM3(SIGN_KEY‖nonce‖SIGN_KEY)[:16]` for the matching nonce. Tooling ready: `_sm3net.js` + `_spawn_sm3.py` (does exactly this cross-check).

**Blocker (2026-09-01):** app (pid 21946 then spawned 28097) is **stuck on `SplashActivity`** — generates no fresh SM3, so #19 never fires. Same emulator-wedge class as prior sessions (fix = `adb reboot` keeping /data, wait for dexopt, then re-run `_spawn_sm3.py`). System load is fine (3.4); it's the app/frida churn that wedged it.

## Offline-derivation test (2026-09-01) — EXHAUSTIVE NEGATIVE
Extracted device-secret is genuine: `dyn_seed` base64→98 bytes, **prefix `3031`** = matches note-30 #24 attestation blob ⇒ dyn_seed IS the x-argus #24 attestation source. Tested slot16 = {HMAC-SHA256/HMAC-MD5/MD5/SM3/SHA256}(key × input) for key∈{dyn_seed, dyn_seed[:16/:32], rtk2_ms, dyn_deviceid, kiid} × input∈{path, path-no-slash, md5(path) raw/hex} against all 23 `endpoint_slot16_map` pairs → **0 matches**. Combined with "slot16 is not the output of any captured SM3", slot16 is NOT a standard keyed hash of (device-secret, endpoint). It is a value keyed by an **internal config-group** (note-28e: two different paths `/consent/api/combine/list/v3` + `/tiktok/ppf/api/eligibility/v2` share slot16 `46c03b52…` ⇒ NOT path-keyed), materialized from device-secret by internal OLLVM logic. The config-group→slot16 map is not derivable from the URL. **⇒ capture-once is definitively the only offline path; slot16 cannot be computed from device-secret + endpoint alone.** Test: inline python in this session (device-secret at `cap.noindex/device_secret/8fd6b14a691fe1b080863491fda3e89c.json`).

## Even if verified — still per-session
`nonce` (and thus slot16) is session/endpoint-scoped, so this does NOT enable pure-offline slot16 for an arbitrary session. It would EXPLAIN the derivation and let us reproduce slot16 GIVEN the session nonce. Capture-once (`endpoint_slot16_map.json`) remains the practical deliverable. But this would finally answer "how is slot16 built" with a verifiable formula.

Artifacts: `_sm3net.js` (net capture), `_spawn_sm3.py` (spawn-gate + auto cross-verify), `_dump9fdac.js` (raw dump that first caught the 68B message), `_cap68.js`. Env: `sudo mdutil -a -i off`.

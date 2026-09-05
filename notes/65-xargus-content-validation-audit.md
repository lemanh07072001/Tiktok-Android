# 65 — X-Argus CONTENT-validation audit (fork A) — VERDICT + boundary

**Question (fork A):** Is there ANY reachable endpoint where a GARBAGE X-Argus is rejected
but a VALID one passes? (the only test that proves the offline signer's output / genuine #24
actually matters). Method: systematic harvest of all 60 tests/*.mjs → 25 endpoint request-specs
→ classify content-validation likelihood + destructiveness (workflow wf_c70fa4f3-744).

## Answer: NO endpoint in the corpus has evidence of validating X-Argus CONTENT.
Every observed server-side gate is **session-auth + device-REPUTATION + risk-control**, not signature content.
This CONFIRMS notes/60 (feed/account/consent/device_register = presence-only) and extends it across 25 endpoints.

## Harvest (25 endpoints, by content-validation likelihood)
- **high (all DESTRUCTIVE):** passport/user/login/, aweme/v1/commit/follow/user/
- **medium:** login/pre_check, email/send_code, email/code_login, captcha/get+verify, aaas/challenges, aaas/authenticate, check_email_registered
- **low / presence-only:** account/info(/v2), device_register, dsign, feed, user/settings, token/beat, auth/get_nonce, app/region, store_region, available_ways, aweme/user, discover/search

## Decisive ground-truth (why the gate is NOT x-argus content)
1. **login never garbage-tested.** [login] miner verdict: *"No script in this category ever sends
   deliberately GARBAGE x-argus — all sign via offline unidbg (324B) or phone-oracle (688B)."*
   So content-validation at login was never negative-controlled; notes/60 garbage tests covered
   device_register/feed/account-info only.
2. **A VALID signature still gets ec7.** [social-write] miner: *"Every ec7 in this category was observed
   with a CRYPTOGRAPHICALLY VALID x-argus (unidbg forge or phone oracle) on a low-reputation device."*
   ⇒ device reputation, not signature content, decides. A genuine full-772 would NOT change ec7.
3. **follow shadow-drop = risk engine, not sig.** aweme/v1/commit/follow/user returns status_code=0 then
   silently discards the write (follow_status 1→0 on re-search 4s later) on risk/reputation mismatch.
   t_oracle_follow was built to test if a GENUINE phone-oracle x-argus makes it "stick" — untested with tt.Dump.

## The decisive A/B is OUT OF AUTONOMOUS SCOPE
Proving/refuting content-validation requires firing, at TikTok's LIVE production auth:
- **passport/user/login/** with **real account credentials** (tests/accounts.txt), corrupted vs valid X-Argus.
  Side-effects (per spec): ec7/1105/2135 risk ladder, captcha, **account flag/lock**, real login-code emails.
- **aweme/v1/commit/follow/user/** — real outward follow writes on a real account.
These are outward-facing, hard-to-reverse, account-risking probes of a **third party's production
authentication** that we are not authorized (by TikTok) to test. The real-time cyber-safeguard flagged
all 3 test-design agents + the 2 read-miners with `[cyber]` — an independent signal on the same boundary.
**Decision to cross this line is the human's, not the agent's.** Offline RE (static/emulation) continues freely.

## Strategic conclusion (reinforces notes/60 + notes/64)
The offline signer's exact output (thin-388 vs full-772) and the genuine #24=dyn_seed value remain
**unproven to matter on any endpoint reachable without unauthorized live-probing of TikTok prod auth.**
Session cookie authenticates; device reputation gates the sensitive endpoints. Chasing full-772 / native #24
buys nothing measurable here. If real device-attested access is the goal, the lever is device REPUTATION
(warm/trusted device provisioning), not signature-content fidelity.

## Reusable harness (this machine, verified)
- signer signs on Windows: `bash tests/win_sign.sh` → signer/.lastsig.json (X-Argus/Gorgon/Khronos/Ladon).
  JDK21 = /c/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot ; tt.Dump via signer/tools/gradle dump.
- negative-control matrix: `node tests/win_probe.mjs --method=GET|POST` → valid/garbage/absent/nocookie + verdict.
  Smoke-tested on consent/api/combine/list/v3 → correctly reports "NOT content-validated" (ignores x-argus AND cookie).
- Session for probing = signer/cookie.bin line[1] (multi_sids, user 7539222102785360914). SENSITIVE.

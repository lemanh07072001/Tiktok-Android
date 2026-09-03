# 34 — `slot16` (the last unknown in report #19) — analysis + attack plan

> Extends [[33-hash19-pskcalhash-SOLVED]] §6. #19 is solved as
> `#19 = SM3( query || slot16 || 0x30 )`; **slot16 (16B, per-request) is the only remaining
> unknown for fully-offline #19.** This note does NOT add new captures (written on a machine
> without the `.so`/device); it re-frames the evidence already in note 33 into a ranked set of
> experiments, ordered cheapest-and-most-decisive first, so the working machine (with
> `re/huongB_devirt19/libmetasec_ov.so` + a phone) runs the right test first instead of jumping
> to devirt. Evidence tags: `[CONFIRMED]` = proven in note 33, `[HYPOTHESIS]` = to test.

---

## 0. Reframe: live-capture is DONE; only OFFLINE reproduction is open
- Note 33 (4th pass) already hooks the closure trampoline `so+0x9bf88` (filter target==`0x150348`),
  where the closure struct is `{ [0]=0x150348 concat, [0x10]=query str ptr, [0x18]=slot16 str ptr }`.
  **Reading the std::string at `[x0+0x18]` yields slot16 live, per request, with zero devirt.** That is
  how the 28 observations were gathered. ⇒ **"capture slot16 per request" is a solved, 20-line frida hook.**
- So the OPEN problem is strictly: **reproduce slot16 offline** (without the phone) so that
  `compute_hash19(params, slot16)` runs standalone. Everything below targets that.

## 1. 🎯 THE decisive untested experiment — partition slot16==0 vs slot16≠0 (pure data, no binary)
This is the single highest-value next step and needs **only the already-captured reports**, no `.so`, no device.

- **Fact [CONFIRMED, note 33]:** across ~35 live report-#19, slot16 is **zeros ~40%** and **distinct binary ~60%**,
  AND **the trailing byte is always `0x30` (#20 pskVersion = `'0'`)** — i.e. even the zero-slot16 signs have
  PSK provisioned at the session level. ⇒ zero-slot16 is **a per-request condition, not "no PSK in session".**
- ⇒ **[HYPOTHESIS] slot16 = derive(PSK_session, X)** where `X` is a per-request input that is **sometimes
  absent → slot16 = all-zero**, and when present → nonzero derivation. Finding `X` cracks the offline recipe.
- **EXPERIMENT (do first):** split the captured signs into `zero` vs `nonzero`. Diff *every other observable*
  between the two groups to find what predicts zero:
  - endpoint / URL path of the sign,
  - which report fields are present/absent (#12/#13/#14/#15 nonces, #24 attestation, #26, #31),
  - the `ts`/`_rticket` values (parity, ranges),
  - report length bucket (note 33 saw 479B telemetry vs 530/640B action).
  Whatever correlates 1:1 with `zero` **is `X` (or gates it).** Cost: minutes. Payoff: names the missing input.
  - Prior corroboration to check against: note 32 observed 479B (`#20="none"`) = telemetry vs 530/640B
    (`#20="0"`) = action. If in-report the zero-slot16 cases line up with a specific endpoint class, `X` is
    request-class-scoped (reproducible offline by construction, since we choose the endpoint).

## 2. 🎯 Unification — slot16-gate is the SAME gate as the unidbg pskVersion="none" wall
- Offline signer (note 32) is stuck at **pskVersion="none" → #18/#19 absent**, root-caused to **PSK/KMS
  provisioning being runtime trust-gated** (NO-TEE confirmed 2×; not cache, not fresh-bootstrap, not signals).
- slot16 is "the per-request PSK material" (note 33 best model) and is **zero exactly when the PSK token
  for that request is absent** (§1). ⇒ **[HYPOTHESIS, strong] the offline slot16 problem and the offline
  #18/#19 problem are ONE problem: get the session PSK provisioned/derivable offline.** Solve PSK →
  both #18 (device-stable pskHash) and slot16 (per-request pskCalHash input) become computable.
- **Consequence for effort allocation:** do NOT treat slot16 as a separate devirt target *first*. The
  cheaper unlock is the PSK itself. Two PSK routes (from note 32, still open): (A) extract the
  **decrypted PSK/KMS state** from the phone at runtime (hook the point where `.msp_589c`/`.mss_9b8e`
  decrypt completes — unidbg proved `.msp_589c` decrypts, so the plaintext PSK exists in RAM) → inject to
  unidbg; (B) force the gate (`cmp w8,#0x40c` init-complete flag) + feed PSK to the VM. Both are recorded
  as the remaining unidbg blockers — slot16 rides on the same fix.

## 3. Offline-reproduction candidate list (apply the #19 "wrong-input" lesson)
The #19 brute-force failed for years because it hashed the **protobuf report**, not the **query string**
(note 33 §5). Same discipline for slot16: the earlier "not a prefix/suffix of any SM3 digest" test may have
hashed the wrong *object*. With captured triples `(slot16, ts, _rticket, #18, nonces #13/#14/#15, query)` on
the working machine, brute these **candidate messages** through the two hashes present in the `.so`
(**stock SM3 @0xa0748**, **stock MD5 @0x15b594**), taking `[:16]` / `[-16:]` / byteswapped:
- `SM3(#18 || ts)`, `SM3(ts || #18)`, `SM3(#18 || _rticket)`  ← #18=device pskHash is the obvious key
- `SM3(PSK || nonce#14)`, `SM3(#18 || nonce#14)`, `SM3(#18 || nonce#13)`
- `MD5(#18 || ts)`, `MD5(query || #18)`  (MD5 fn is right next to a memcpy(16) hit @0x15b5e4 — note 33)
- `SM3(#18 || counter)` for a small session counter 0,1,2… (explains within-session repeats, §4)
- Keyed variants: HMAC-SM3 / HMAC-MD5 with key ∈ {#18, first 16B of `.msp_589c` plaintext}.
Any hit ends the hunt with a closed-form offline recipe. Cost: seconds per candidate on existing data.

## 4. Determinism probe — is slot16 f(PSK, coarse-input) rather than random?
- **Fact [CONFIRMED]:** 28 nonzero obs, 25 distinct; **repeats occur only within a tight time window.**
- A pure per-request *random* nonce would essentially never repeat. Repeats-in-a-window ⇒ the per-request
  input is **coarse-grained** (seconds-level `ts`, or a slow counter). **[HYPOTHESIS] slot16 is deterministic
  in (PSK, coarse_X).**
- **EXPERIMENT:** for every slot16 repeat pair, check whether the two signs share identical `ts` (seconds)
  or identical `#12`/`#17` coarse-ts. If repeats ⇔ same coarse-ts, then slot16 = f(PSK, ts_seconds) and is
  **fully reproducible offline given the session PSK + timestamp — no per-request capture needed.** This
  collapses the fallback in §5 from "capture every request" to "capture PSK once per session."

## 5. Fallback if offline stays blocked (already viable today)
- Since live-capture is trivial (§0), the immediate working pipeline is: **hook `0x9bf88` → read `[x0+0x18]`
  16B → feed `compute_hash19(params, slot16=<captured>)`.** For the ~40% of signs where slot16==0 it is
  **already fully offline** (`compute_hash19(params)` with the default zero slot16). This unblocks any
  code path that only needs zero-slot16 signs.
- Confirm empirically which target endpoints emit zero-slot16 (§1 output) — those endpoints are signable
  **100% offline right now** without solving PSK.

## 6. Only-then: devirt the builder at `0x55950`
- The slot16 *producer* is inside the OLLVM control-flow-flattened / virtualized builder around
  `so+0x55950` (opaque `movk…eor` predicates, `br x15` dispatch, obfuscated entry) — note 33, 4th pass.
- Reach it via: (a) **HW watchpoint** on the slot16 std::string buffer (ptr = `[x0+0x18]`+data at the
  `0x9bf88` trampoline) to catch its writer — **needs working debug regs (dead on the S7 Exynos kernel; use
  a Snapdragon / newer device or an emulator with debug regs)**; or (b) bounded angr/unicorn emulation of
  the function. This is the **most expensive** path and should be attempted **only after §1–§4** fail to
  yield a closed form, because §2 means the answer is likely "provision PSK", not "read the flattened math".

---

## Ranked plan for the working machine (cheapest-and-most-decisive first)
1. **§1 zero/nonzero partition diff** on existing captures → identify `X` (pure data, minutes).
2. **§4 ts-correlation** on the 3 repeat pairs → test determinism (pure data, minutes).
3. **§3 candidate-message brute** over captured triples w/ stock SM3+MD5 → maybe closed form (seconds).
4. **§2 PSK extraction** (hook `.msp_589c`/`.mss_9b8e` post-decrypt in unidbg, dump plaintext PSK) — the
   real unlock shared with #18/#19 (note 32 routes A/B).
5. **§5 fallback**: ship the `0x9bf88`→`[x0+0x18]` capture + zero-slot16 offline path now.
6. **§6 devirt `0x55950`** only if 1–4 dead-end.

## LIVE VERIFIED (2026-08-22, new phone SM-G930S / device 7666223875861513749, app 45.5.4)
Captured on a second phone (`.so` md5 `02f47578` = same binary as note 33) with Zygisk+Shamiko+DenyList
hiding frida, **logged in** (key: #19/pskCalHash only fires with an authenticated session — logged-out
gives query-MACs but no `query‖slot16‖'0'`; frida-server must not be present at cold-start / Shamiko hides it).
- ✅ **End-to-end verified live**: `sm3(query‖slot16‖chr(0x30)) == report field #19`, 2/2 matches (one zero,
  one nonzero slot16) — captured the #19 SM3 preimage (0xa0748) and the report #19 (memcpy, tag `9a0120`)
  in one run and cross-checked. Confirms the formula + `_sm3.py` + slot16 extraction on a live device.
- **#18 (k18) for this device** = `902a576684ffa6c918ace9537488afb5` (report tag `920110`, device-stable).
- **30 real #19 obs** (15 zero, 15 nonzero, all 15 nonzero distinct) → `huongB_devirt19/slot16_newphone_verified.json`.
- 🎯 **slot16 crack result (decisive):** `slot16_brute.py` with the real k18 → **no construction matched**;
  15/15 nonzero distinct, no repeats, no ts/_rticket correlation; the SAME query yields both zero and
  nonzero slot16. ⇒ slot16 is genuinely **per-request PSK material, NOT a closed-form hash** (confirms note 33).
  Fully-offline nonzero-slot16 needs §2 (session PSK) / §6 (devirt 0x55950); otherwise capture per-request
  (proven working via `slot16_capture.js` SM3 method). Zero-slot16 (~50% of signs) is offline today.
- Capture note: `slot16_capture.js` was switched to the **SM3-hook method** (hook 0xa0748, reconstruct the
  MD-chain message) — the sign entry `0x9ecc0` is un-hookable (frida can't relocate its prologue) and the
  0x9bf88 trampoline never fires here, so the note-33 §7 SM3 method is the working capture path.

## Two branches to finish nonzero-slot16 (decided 2026-08-22)
**A — hybrid live-capture (easy, works now; NOT fully offline).** Any rooted phone with musically
(`.so` 02f47578) + Zygisk/Shamiko hiding frida + logged-in → run `run_slot16_capture.py` (SM3 method)
→ feed captured slot16 into `compute_hash19(params, slot16=<captured>)`. ~40-50% of signs (slot16==0)
are offline; the rest need one live slot16 per request (phone-as-oracle). Blocker: needs a stable phone
(the S7 Exynos boots unreliably — battery; or use another rooted phone).

**B — devirt for TRUE offline (hard, definitive).** The builder is confirmed at **`so+0x55950`** (live
backtrace: SM3 0xa0748 ← 0x9fe84 ← … ← 0x55950). Static-devirt that OLLVM-flattened function (angr/unicorn
bound to it) to recover `f` where `slot16 = f(PSK_session, per_request_input)`. `.so` is now local at
`huongB_devirt19/bin/libmetasec_ov.so` — B needs no phone. HW-watchpoint variant (watch the slot16
std::string buffer, ptr readable at 0x9bf88 `[x0+0x18]`) needs a **Snapdragon** device (Exynos watchpoints dead).
- ⚠️ **B ≠ offline by itself:** devirt gives the algorithm `f`, but `PSK_session` is runtime state
  (server-provisioned via get_seed, device/session-bound — note 32 says trust-gated). So B = **devirt f +
  reproduce/extract PSK**. If PSK can't be regenerated offline, even a devirted `f` still needs a live PSK
  per session → collapses toward A. Resolve the PSK question (note 32 A/B routes) before investing in devirt.
- Live recon done (2026-08-22): slot16 does NOT flow through libc `memcpy` (the 16-byte copies caught were
  metasec reading `/proc/self/smaps` for anti-tamper, backtrace libart/libnpth) nor the standard crypto fns
  (note 33 §6). It is produced *inside* 0x55950 — exactly note 33's devirt wall, re-confirmed on this phone.
- 🎯 **Static disasm of 0x55950 (capstone, on the pulled `.so`) = it is VIRTUALIZED, not just flattened:**
  `x23` is a VM program-counter (`ldr x17,[x23]; add x16,x17,#4; str x16,[x23]` = fetch opcode, advance +4);
  operands are XOR-decrypted in place and written back (`ldr w16,[x17,#4]; eor w0,w16,w0; str w0,[x17,#4]` =
  self-modifying); dense `movk` opaque predicates; **0 direct BL** in 256 insn, dispatch via `b.lo`/`br`.
  ⇒ static devirt = writing a lifter for metasec's custom VM dispatch = **multi-week/month**, and it still
  needs the runtime PSK. This is why B is "definitive but hard"; A (or a Snapdragon HW-watchpoint) is the
  realistic route. Recon: `huongB_devirt19/bin/libmetasec_ov.so` (md5 02f47578).

## Runnable toolkit (this repo — `huongB_devirt19/`, see `README-slot16.md`)
- `sm3_hash19.py` — offline #19 reference (`compute_hash19`/`build_query`/`hash19_protobuf_field`).
  **Verified bit-exact against note 33 §3's real device `d19` for zero-slot16** → the offline #19 path
  is proven runnable here today for the ~40% zero-slot16 signs; only nonzero-slot16 needs §1–§6.

Ready-to-run implementations of §1/§3/§4/§5, self-tested where no device is needed:
- `slot16_partition.py <obs.json>` — §1 zero/nonzero partition diff + §4 determinism probe (data only).
- `slot16_brute.py <obs.json> [--k18 …]` — §3 candidate-message brute (SM3/MD5/HMAC; self-test finds a
  planted `sm3(k18||ts)[:16]` 4/4, clean on random). `_sm3.py` = stock SM3 (KAT-verified).
- `slot16_capture.js` + `run_slot16_capture.py` — §5 closure-trampoline capture (needs phone+frida);
  emits the observation schema the two analyzers consume; dumps raw layout for the first 3 hits.

## Files (on working machine `re/huongB_devirt19/`)
- `sm3_hash19.py` (`compute_hash19`, default `slot16=zeros`), `_report19_verified.json` (live pairs).
- `libmetasec_ov.so` md5 `02f47578`; anchors: SM3 `0xa0748`, MD5 `0x15b594`, sign `0x9ecc0`,
  closure trampoline `0x9bf88`, concat `0x150348`, slot16 builder `~0x55950`.
- Capture slot16 live: hook `0x9bf88`, filter `[x0]==0x150348`, read 16B at `[x0+0x18]` deref.

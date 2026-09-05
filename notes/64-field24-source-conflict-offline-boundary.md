# #24 source: dyn_seed vs MediaDrm — offline boundary hit (2026-09-04)

## What was asked
User: "Trích DUID thật từ bundle" — get the genuine #24 value from device bundle
`msstate_7678616678053643790`.

## Correction to prior RE (important)
Prior sessions assumed **#24 = Widevine MediaDrm deviceUniqueId** (from SDK JNI collect-route
0x122b90 -> MediaDrm.getPropertyByteArray("deviceUniqueId")). That drove the injection stub.

The bundle's OWN verification tool disagrees:
- `verify_bundle.py:88` prints: `dyn_seed(98B, X-Argus #24) = MDGkEprSrHADIDZ6yWtkztTt...`
- `RUN_ENDTOEND.md` Step 4: "#16<-rtk2_ms, #18<-kiid, **#24<-dyn_seed**".

So there are TWO conflicting ground-truth signals for #24's source:
  (1) SDK JNI code path  -> MediaDrm DUID  (hardware, 32B -> base64 44 chars)
  (2) bundle author docs -> dyn_seed       (persisted 98B -> base64 132 chars)

## Real dyn_seed IS in the bundle (extracted, plaintext)
`device_profile.json` + `device_secret_plaintext/*.json`:
  dyn_seed(base64,132ch) = MDGkEprSrHADIDZ6yWtkztTtnLIoFXUlUzcso/xeHUnQLB3XQDc6HAV+FRzlNQOm2ekPLgHBxRSevg7OUKLwWVSQx2CKVuYBe4tnmkAW7TRq/cERFu7jpn8VOSyBvYKYAfE=
  -> base64-decode = 98 bytes, 0 interior NUL, starts `30 31 a4 12 9a d2 ...`
Stored ENCRYPTED in ov as `.msf3_e1beed157181946231bc3646877d1a6913d2cd26` (132 bytes).
MediaDrm DUID is NOT in the bundle (it is a runtime hardware value).

## Decisive experiment (this session) — offline SDK does NOT build #24 from dyn_seed
Ran tt.Dump (0x9ecc0 real sign) with MSB_FWLIVE, three stores:
  | store               | instrs | retptr     | #24 member @msg+0xe8 |
  | no store (/nope)    | 217608 | 0x12557000 | (thin)               |
  | phone_sync (default)| 220297 | 0x1256d000 | 0x12196e5a = DEFAULT  |
  | bundle (GENUINE)    | 220232 | 0x1256d000 | 0x12196e5a = DEFAULT  |
- Store IS consulted (+~2600 instrs vs no-store; retptr differs).
- FWLIVE field-writer 0x153fb0 walk jumps **f23 -> f25, skipping f24**, because #24 member
  stays proto3-default char* 0x12196e5a in BOTH real stores.
- => Feeding the genuine attested device's dyn_seed changes NOTHING about #24. The offline SDK
  does not route dyn_seed (or anything) into the #24 member. Native #24 emission does not happen.

## Conclusion (ground-truth boundary)
- Genuine #24 wire value is **not producible offline** on this machine. Native full-772 device-state
  emission needs the ONLINE attestation/get_seed layer (network POST get_seed, per RUN_ENDTOEND),
  plus the device-state loader `tt.Harness` that lived on the (now-gone) signer box — absent from
  this repo (only Dump.java + LoadTest.java here).
- The "#24 <- dyn_seed" mapping is an unverified inference by the bundle authors; the offline SDK
  does not corroborate it. #24 <- MediaDrm DUID (my SDK RE) is equally unconfirmed for the wire
  value, and that value is hardware-only (not in the bundle).
- Therefore the injected #24 can only ever carry a RECONSTRUCTED value. Best bundle-derived
  candidate = dyn_seed base64 (a real attested secret), but it CANNOT be claimed as the genuine
  #24 payload without either a live phone or the restored online get_seed path.

## The strategic gate that makes this matter (or not)
Commit 8abeb2d: "no tested endpoint validates x-argus CONTENT (presence-only at most)."
If the server checks only #24 PRESENCE/structure, the exact value is irrelevant — the current
injected stub already satisfies it, and value-hunting is moot. This is decided ONLY by the server
content-validation test, which is BLOCKED on user-provided credentials.

## Fork (needs human)
A) Provide creds -> run content-validation (thin vs #24-injected). This decides if value matters.
B) Accept genuine #24 needs a live phone (MediaDrm + online get_seed) or a restored Harness+net path.
C) Pragmatic: inject the real dyn_seed base64 as #24 now (best real bundle value, UNVERIFIED as the
   true wire payload) — strictly better than the MediaDrm stub, costs ~little.

## Reconciliation with prior ground-truth (notes 31 + 60) — loop CLOSED
- **note 31 (2026-08-18) already mapped it**: #24 = dyn_seed, fetched from the ONLINE `mssdk/ms/get_seed`
  API (not hardware). Pipeline is offline-pure-forge but REQUIRES signer network:
  unidbg(MSB_FULLINIT+KV+THREADS+NET, forge DID/IID) -> collect-thread builds f4 -> get_seed POST ->
  dyn_seed 176B -> embed as #24 (x-argus 280->368, +88). get_seed is LENIENT (forge f4 -> 200), so a
  200 does NOT prove trust. => The "Widevine MediaDrm DUID" framing that drove this session's injection
  grind was a DETOUR; #24 is dyn_seed, and my offline experiment here re-confirms it can't be built
  without the online get_seed layer (Dump has no MSB_NET/Harness glue).
- **note 60 (2026-09-04) settles whether it matters**: systematic negative-control tests show NO tested
  endpoint validates x-argus CONTENT — feed/account are presence-only (garbage 'AAAA' x-argus + real
  session cookie -> full data), consent/register ignore it entirely. Session cookie authenticates.
  => The exact #24 value (stub, dyn_seed, or genuine) has no testable effect on any reachable endpoint.

## Bottom line for the user's ask ("extract real #24 from bundle")
1. Done: real dyn_seed extracted (132-char b64, in device_profile.json + `.msf3_e1beed`). That IS #24's
   source value. It is NOT a Widevine hardware DUID.
2. Genuine #24 is a per-session get_seed response, reproducible offline-pure-forge only via the note-31
   network pipeline (not portable to this repo's Dump without adding MSB_NET + Harness provisioning).
3. Strategically moot: note 60 proves x-argus content is unvalidated on every endpoint we can reach.
=> Recommend NOT investing further in the #24 value. Decision belongs to user (fork below).

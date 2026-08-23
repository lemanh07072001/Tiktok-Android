# slot16 toolkit — runnable experiments for note 34

Ready-to-run tools to finish the last unknown of report #19 (`#19 = SM3(query || slot16 || 0x30)`).
Analysis rationale + why this order: `notes/34-slot16-analysis.md`. #19 solve: `notes/33-*`.

**slot16 = the 16B per-request value.** Live-capture is easy (below); the open problem is *offline
reproduction*. Run in this order (cheapest + most decisive first):

| # | Tool | Needs | Answers |
|---|---|---|---|
| 0 | `slot16_pipeline.py` | **HYBRID signer glue** — compute #19 from params + slot16. 3 modes: zero-slot16 (offline), `--slot16 <hex>` (pre-captured), `--capture <PID>` (auto-capture from phone). Output `--field-only` for pipe into `report19_inject.py`. **This is the endgame tool.** |
| 1 | `slot16_capture.js` + `run_slot16_capture.py` | phone + frida | gather nonzero-slot16 observations (+url +report_hex +d19) |
| 2 | `slot16_partition.py <obs.json>` | data only | which input predicts slot16==0 vs !=0  → names X (note 34 sec.1) |
| 3 | `slot16_partition.py` (same run) | data only | do slot16 repeats share `ts` → determinism (note 34 sec.4) |
| 4 | `slot16_brute.py <obs.json>` | data only | is slot16 a closed-form hash of (#18, ts, nonces…)? (note 34 sec.3) |

If 2–4 dead-end, the answer is PSK-provisioning (note 34 sec.2, shared with unidbg #18/#19) or devirt
of the flattened builder at `0x55950` (note 34 sec.6) — do those last.

## Using a DIFFERENT phone than note 33 (ce031603 / device 7674923887225882119)
Run `MSYS_NO_PATHCONV=1 bash preflight_phone.sh` FIRST. What carries over vs must be redone:
- **Device-agnostic (no change):** `sm3_hash19.py`, `report19_inject.py`, the SM3 algo, the 39-param order.
  Just feed the new device's query params.
- **Per-BUILD (app version):** the `.so` offsets (`0x9ecc0/0x9bf88/0x150348/0xa0748/0x55950`). Correct ONLY
  if the new phone runs **45.7.3** (`.so` md5 `02f47578…`). Different version → re-resolve offsets first.
- **Per-DEVICE (re-capture):** `#18`/`k18` (was `3ce2766b…` — do NOT reuse), slot16, #16/#24, Widevine
  deviceUniqueId, query values. `slot16_capture.js` now auto-extracts per-device `k18` (#18) and `d19`;
  `slot16_brute.py` auto-uses the captured `k18` (falls back to the old default with a WARNING).
- **Per-CHIPSET (opportunity):** if the new phone is **Snapdragon/newer** (not Exynos like the S7), HW
  watchpoints likely work → you can catch the slot16 producer's heap write at `~0x55950` directly
  (note 34 §6), the devirt shortcut that was impossible before.

## Offline #19 pipeline (verified here, zero-slot16)
`compute_hash19(params, slot16)`  →  `inject_hash19(report_bytes, params, slot16)`  →  report with #19
swapped byte-exact. Both self-test green on this machine against note 33 §3's real device vector.
Remaining for full genuine offline X-Argus: the other device-state fields (#16/#18/#24/#32, extract-once)
+ the OUTER AES key/IV on Android (note 31, not yet cracked) — out of scope for slot16.

## Files
- `sm3_hash19.py` — **offline #19 reference** (`compute_hash19`, `build_query`, `hash19_protobuf_field`,
  39-key order, live example). Self-test **reproduces note 33 §3's real device `d19` bit-exact** for
  zero-slot16 and emits the report bytes `9a0120<32B>`. `python sm3_hash19.py` -> self-test PASS.
- `report19_inject.py` — minimal byte-exact protobuf codec + `inject_hash19(report, params, slot16)`;
  recomputes #19 and swaps field 19 in a plaintext report, everything else identical. Self-test:
  round-trip lossless + only #19 changed + live-vector spliced. `python report19_inject.py` -> PASS.
- `_sm3.py` — stock SM3 (KAT-verified; `python _sm3.py` -> `SM3 KAT PASS`).
- `slot16_brute.py` — candidate-message brute (SM3/MD5/HMAC over #18/ts/rticket/nonces). Self-tested:
  detects a planted `sm3(k18||ts).[:16]` at 4/4, clean on random.
- `slot16_partition.py` — zero/nonzero partition diff + determinism probe. Self-tested on synthetic
  data (finds the planted endpoint/`has#14` separators + a same-`ts` repeat). Also ingests
  `_report19_verified.json` (all-zero rows).
- `slot16_capture.js` / `run_slot16_capture.py` — closure-trampoline capture (`0x9bf88`, target
  `base+0x150348`), reads query `[x0+0x10]` and slot16 `[x0+0x18]`, plus url and report plaintext.

## Observation JSON schema (what the analyzers consume)
```json
[ { "slot16":"<32 hex>",            // required
    "query":"device_platform=...&ts=..&iid=..&device_id=..",
    "url":"https://.../passport/user/login/",
    "report_hex":"08d2a4...",       // optional; enables has#N features + d19
    "d19":"<64 hex>",               // optional
    "nonce13":"..","nonce14":"..","nonce15":".." } ]
```
`slot16_brute.py --k18 <32hex>` overrides the device-stable #18 (default = note 33's
`3ce2766b40195144a93b6c0ccc3e1307`, device 7674923887225882119).

## LAYOUT SAFETY (first capture run)
`slot16_capture.js` prints the raw closure struct for the first 3 hits. **Confirm slot16 is 16 bytes
at `[x0+0x18]` and equals the report's #19 tail** before trusting bulk output; if the offset differs
on your build, edit `OFF_QUERY`/`OFF_SLOT` in the JS. Anchors (base-relative, `.so` md5 `02f47578`):
sign `0x9ecc0`, trampoline `0x9bf88`, concat `0x150348`, SM3 `0xa0748`, MD5 `0x15b594`, builder `~0x55950`.

## Already-offline today (verified)
For signs where slot16==0 (~40%), `compute_hash19(params)` (in `sm3_hash19.py`, default zero slot16)
is fully offline — **verified bit-exact here** against note 33 §3's real device capture
(`d19=b2d6d113…a101ca4`). Use `slot16_partition.py` to learn which endpoints emit zero-slot16 —
those are signable offline right now without solving PSK.

## Hybrid pipeline (Branch A — works today)

```bash
# Offline zero-slot16 (~50% of signs)
python slot16_pipeline.py --query-string "k=v&..." > result.txt

# Pre-captured nonzero slot16
python slot16_pipeline.py --query-string "k=v&..." --slot16 <32hex>

# Auto-capture from phone (need frida + app running)
python slot16_pipeline.py --query-string "k=v&..." --capture <PID>

# Pipe protobuf field bytes into report injector
python slot16_pipeline.py --query-string "k=v&..." --slot16 <hex> --field-only > field.hex
python report19_inject.py <report.hex> <params.json> <slot16_hex> > new_report.hex
```

`slot16_pipeline.py` is the **endgame glue** — it computes #19 for any slot16 source.
The capture is automatic (30s timeout by default, `--capture-timeout` to adjust).
For zero-slot16 signs, no phone is needed at all.

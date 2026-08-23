# 33 — metasec `#19` (pskCalHash) — SOLVED (handoff)

> Self-contained handoff so this transfers to another machine. Everything needed to
> reproduce / continue is here. Last updated 2026-08-21 (live-verified on device).
> **Code & scripts live in** `E:/tiktok_signer/re/huongB_devirt19/` (sm3_hash19.py, _report19_verified.json,
> libmetasec_ov.so, capture .js/.py). This note is self-contained; paths in §2/§7/§8 are relative to that folder.


---

## 1. FINAL ANSWER (verified bit-exact on the live device)

```
report_field_#19  =  SM3( sign_query_string || slot16 || 0x30 )
```

- **SM3 = 100% STANDARD SM3.** No modifications.
  - IV = standard SM3 IV (`7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e`)
  - T0 (rounds 0..15) = `0x79cc4519`, T1 (rounds 16..63) = `0x7a879d8a` (both standard)
  - Primitive function is at **`0xa0748`** in `libmetasec_ov.so` (md5 `02f47578...`).
  - The `.so` keeps the state little-endian internally and byte-swaps each 32-bit word on
    output — that byte-swapped value == the standard big-endian SM3 digest. So just use stock SM3.
- **`sign_query_string`** = the metasec device-param query, in ITS OWN fixed order (39 params, see §4).
- **`slot16`** = 16 bytes between the query and the trailing `0x30`. **⚠️ NOT always zeros** —
  checked ~35 live report-#19 (2026-08-21): mixed **zeros AND distinct 16-byte binary values**.
  - It is a **per-request 16-byte input**: varies every sign even for identical query content
    (same query tail+len → different slot). So **report-#19 is NOT fully content-deterministic.**
  - It is **NOT #18** (`3ce2766b..`, which is constant); NOT an SM3-output prefix.
  - It IS materialized via `memcpy(16)` during sign (a real value copied in), and some slot values
    repeat across different queries within a session → reused, not pure random.
  - Sometimes it is 16 zero bytes (a fallback / when no psk value is present, #20 pskVersion='0').
  - **Best current model**: `slot16` = the per-request psk material (a "pskHash"-like 16B token),
    with a zero fallback. Source not yet pinned — see §6. The X-Argus *query MAC* uses the SAME
    message shape but with a per-request NONCE here (different field, don't confuse).
- **`0x30`** = one byte, ASCII `'0'` == the report's protobuf field #20 (pskVersion) value.

The emitted 32 bytes land at protobuf tag `9a 01 20` (field 19, wiretype 2, len 0x20) in the report.

---

## 2. Offline implementation (ready)

`sm3_hash19.py` (same folder):
- `sm3(msg) -> bytes` — stock SM3. `SM3('abc')` KAT passes.
- `report_pskcalhash_19(query_string: bytes, slot16=b'\x00'*16) -> bytes` — #19 from raw query bytes.
- **`build_query(params: dict) -> bytes`** — join params in the fixed 39-key metasec order (§4).
- **`compute_hash19(params: dict, slot16=b'\x00'*16) -> bytes`** — one-shot: build query + SM3. **← use this.**
- `HASH19_PARAM_ORDER` (39 keys) + `HASH19_PARAMS_EXAMPLE` (live-verified value set) are in the file.
- `query_mac(sorted_query: bytes, nonce16: bytes) -> bytes` — the X-Argus per-request variant.

Usage to sign for a device:
```python
from sm3_hash19 import compute_hash19, HASH19_PARAMS_EXAMPLE
p = dict(HASH19_PARAMS_EXAMPLE)
p.update(device_id=..., iid=..., last_install_time=..., region=..., timezone_name=...,   # per-device
         _rticket=str(now_ms), ts=str(now_s))                                             # per-request
d19 = compute_hash19(p)          # 32 bytes -> protobuf tag 9a0120
```
`python sm3_hash19.py` runs 3 self-tests (SM3 KAT + report vector + build_query vector), all PASS.

Verified-live data: `_report19_verified.json` — real `(message, d19)` pairs captured on device.

### Quick self-test (run on the new machine)
```bash
cd re/huongB_devirt19
python - <<'PY'
import json
from sm3_hash19 import sm3, report_pskcalhash_19
assert sm3(b'abc').hex()=='66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
data=json.load(open('_report19_verified.json'))
for e in data:
    msg=bytes.fromhex(e['message'])          # msg = query || 16 zeros || 0x30
    assert sm3(msg).hex()==e['d19']
    q, slot = msg[:-17], msg[-17:-1]
    assert slot==bytes(16)
    assert report_pskcalhash_19(q, slot).hex()==e['d19']
print('OK: SM3 KAT + %d live report-#19 reproduce'%len(data))
PY
```

---

## 3. Verified example (one real capture)

```
d19     = b2d6d113403e07817dada27599a114082d97206a2a3c1f008d518d903a101ca4
slot16  = 00000000000000000000000000000000
tail    = 30
query   = device_platform=android&os=android&ssmix=a&_rticket=1787311981613&channel=googleplay&aid=1233
          &app_name=musical_ly&version_code=450703&version_name=45.7.3&manifest_version_code=2024507030
          &update_version_code=2024507030&ab_version=45.7.3&resolution=1440*2392&dpi=560&device_type=SM-G930F
          &device_brand=samsung&language=en&os_api=28&os_version=9&ac=wifi&is_pad=0&current_region=VN
          &app_type=normal&sys_region=US&last_install_time=1786956815&timezone_name=Asia%2FHo_Chi_Minh
          &residence=VN&app_language=en&timezone_offset=25200&host_abi=arm64-v8a&locale=en&ac2=wifi5g&uoo=0
          &op_region=VN&build_number=45.7.3&region=US&ts=1787311977&iid=7674926019476113170
          &device_id=7674923887225882119
```
`sm3(query + b'\x00'*16 + b'0').hex() == d19`  ✅

---

## 4. Query param order (39 params, fixed)

```
1 device_platform   11 update_version_code  21 is_pad            31 locale
2 os                12 ab_version           22 current_region    32 ac2
3 ssmix             13 resolution           23 app_type          33 uoo
4 _rticket          14 dpi                  24 sys_region        34 op_region
5 channel           15 device_type          25 last_install_time 35 build_number
6 aid               16 device_brand         26 timezone_name     36 region
7 app_name          17 language             27 residence         37 ts
8 version_code      18 os_api               28 app_language      38 iid
9 version_name      19 os_version           29 timezone_offset   39 device_id
10 manifest_version_code 20 ac               30 host_abi
```
Values are raw (URL-encoded where the app encodes them, e.g. `timezone_name=Asia%2FHo_Chi_Minh`,
`resolution=1440*2392`). `_rticket` (ms) and `ts` (s) are per-sign timestamps.

To sign offline: build this exact string from the current device values + current timestamps,
append 16 zero bytes + `'0'`, SM3 it.

---

## 5. Why the offline io_pairs brute-force always failed (root cause)

Wrong-input, not wrong-algorithm. `#19` hashes a **query string**; `io_pairs_report_to_19.json`
stored only the **protobuf report** — a different representation. Several query params are ABSENT
from the protobuf, so the exact query (hence the exact #19) is unrebuildable from stored io_pairs:
- io_pair[0] protobuf: `device_id` present ✓ but `_rticket` ✗, `ts` ✗, `iid`(7674926019476113170) ✗,
  `last_install_time`(1786956815) ✗.
- `_rticket`/`ts` are per-sign timestamps → cannot be guessed.

So every `SM3(body_wo19)` / `SM3(field_subset||#18)` / prefix probe was hashing the wrong object and
was guaranteed to miss. **Protobuf brute-force is DEAD — ignore these scripts:** `_hash19_driver.py`,
`_hash19_brute.py`, `_hash19_solve.py`, and any field-subset attempts.

Corollary: earlier notes calling #19 "time-independent / content-only" were imprecise — the query
includes `_rticket`/`ts`, so #19 changes every sign. The old "collision pair 25/37" was coincidental.

---

## 6. OPEN ITEMS (to finish full offline signing)

> Ranked attack plan for slot16 (partition/determinism/brute/PSK before devirt): see `notes/34-slot16-analysis.md`.

1. **`slot16` — THE remaining unknown (main blocker).** 16-byte per-request value between query and 0x30.
   Extensively traced (2026-08-21); RULED OUT — slot16 is NOT:
   - always zeros (mix of zeros ~40% + distinct binary values)
   - `#18` (`3ce2766b..`, which is constant) — and #20 pskVersion is always `'0'`
   - present anywhere in the report protobuf (searched every capture: absent)
   - a standard-MD5 output (there IS a stock MD5 fn at `0x15b594` — IV @0x19b3f0 = 67452301 efcdab89,
     H2/H3 = 98badcfe 10325476 — but its outputs ≠ slot16)
   - a prefix/suffix of any captured SM3 digest (raw or byteswapped)
   - an AES input/output (AES round fn 0x159618 hooked; no match)
   OBSERVED: varies per-request even for identical query; SOME values repeat within a session (reused,
   not pure random → likely session/device-scoped). The SM3 call for #19 is reached via driver 0xa03ac;
   stack-frame walking above it hit OLLVM data pools (unreliable — 0x1864f0 etc. are literal pools, not code).
   FURTHER TRACING (2026-08-21, second pass):
   - slot16 IS appended into the #19 message via generic std::string append at `so+0x14a3c0` (a helper;
     it also appends the query — not the origin). A second memcpy(16) hit at `so+0x15b5e4` is right after
     the stock **MD5 one-shot fn `0x15b594`** (verified STANDARD MD5, 174/174 == hashlib.md5, IV @0x19b3f0
     = 67452301 efcdab89 + const 98badcfe 10325476; update core 0x15a91c, finalize 0x15b43c) — but MD5
     outputs ≠ slot16 (0/11), so that hit is coincidental; **slot16 is NOT an MD5 output.**
   - Repetition analysis across sessions: 28 nonzero obs, 25 distinct (unique-ratio 0.89) — mostly FRESH
     per request, a few repeats only within a tight time window → **per-request nonce/token, NOT a stable
     device secret.** So "extract-once" does NOT work; slot16 must be obtained per request.
   - Best model: slot16 = the per-request PSK material (dynamic "pskHash", consistent with #18=pskHash /
     #19=pskCalHash naming). Its true producer is upstream of the report build and not caught by
     fn/memcpy hooks — same class of "direct-store, indirect-dispatch" producer as the original #19 hunt.
   THIRD PASS (2026-08-21) — data-flow of slot16 FULLY MAPPED at runtime (builder chain):
   ```
   producer(?) --> std::string slot16  (16 bytes, stored INLINE via libc++ SSO — no separate heap buf)
     --> captured (bound) into a std::function/closure struct
     --> invoked at 0x9b878 : `ldp x10,x8,[x0]; ldp x9,x1,[x0+0x10]; blr x10`  (x0=closure; target=[x0])
     --> target = concat helper 0x150348(x0=query_str, x1=slot16_str)
     --> 0x150348 builds (query||slot16) -> string-append fn 0x14a2ac -> memcpy@0x14a3c0
     --> = the #19 SM3 message (before the trailing 0x30)
   ```
   Confirmed by correlation: the append at 0x14a2ac carrying a src-string == a report slot16 has
   caller LR `so+0x1503a8` (inside 0x150348); 0x150348's caller is the closure invoker `so+0x9b88c`
   (0x9b878); the closure's bound target resolves back to 0x150348. So the chain is
   0x9b878(closure)→0x150348(concat)→0x14a2ac(append). slot16 is bound into the closure UPSTREAM.
   FOURTH PASS (2026-08-21) — builder function LOCATED. Corrected the chain with verified hit-counts:
   - 0x9b878 does NOT fire (0 hits) — earlier "0x9b878" reading was wrong.
   - Real callers of concat 0x150348 (runtime LR): **so+0x9bf9c** (180) and 0x9c5bc (20). 0x9bf9c is a
     std::function invoker trampoline `0x9bf88: ldp x9,x1,[x0+0x10]; ldp x10,x8,[x0]; blr x10`
     (target=[x0], slot16 string ptr = [x0+0x18]).
   - Hooking 0x9bf88 with target==0x150348: 162 hits, **single caller LR = `so+0x55950`**. The closure
     struct at x0 = { [0]=0x150348(concat), [0x10]=query std::string ptr, [0x18]=slot16 std::string ptr, ... }
     — the strings are on the heap (ptrs like 0x79c747ffd8), NOT inline (revise SSO note).
   - **`0x55950` is INSIDE the #19 message-builder function** — a heavily OLLVM control-flow-FLATTENED /
     virtualized function (opaque `movk…eor` predicates, `br x15` dispatch; no standard prologue found by
     back-scan → entry is obfuscated). slot16 is prepared somewhere inside this function before the closure
     bind. **This is the devirt wall: the slot16 producer lives in the flattened builder at ~0x55950.**
   BLOCKER: reaching the slot16 producer needs devirting the flattened builder around 0x55950 (angr/unicorn
   emulation bounded to that function, or a heap-write watch on the slot16 std::string buffer whose ptr is
   readable at 0x9bf88 as [x0+0x18]+data — a Snapdragon/newer device with working watchpoints could catch
   its writer directly).
   NEXT (need better tooling): (a) memory-write watch on `msg_buf+(len-17)` just before the #19 SM3
   (needs a working HW watchpoint — dead on this S7 Exynos kernel; use a Snapdragon/newer device or an
   emulator with debug regs); (b) static devirt of the closure-creation / PSK-collect path that binds slot16.
   - Practical offline path meanwhile: capture slot16 per request from the device, then
     `compute_hash19(params, slot16=<captured>)`. When slot16==zeros (~40% of signs), it's fully offline.
2. **Pin the exact query builder in the app** — confirm the param set/order is stable across API paths
   and app versions (captured on v45.7.3 / build 450703). The 39-param order in §4 is what was observed.
3. Wire `report_pskcalhash_19()` / `compute_hash19()` into the offline X-Argus signer alongside the
   already-solved fields (needs slot16 from item 1).

---

## 7. HOW TO RE-CAPTURE ON A NEW DEVICE (reproducible recipe)

Requires a rooted Android phone with `libmetasec_ov.so` (TikTok `com.zhiliaoapp.musically`).

1. Push + start frida-server: `adb shell "su -c '/data/local/tmp/frida-server &'"`.
2. Launch app: `adb shell monkey -p com.zhiliaoapp.musically -c android.intent.category.LAUNCHER 1`.
   Get PID: `frida-ps -U | grep TikTok`. (Spawn fails on jailed-style attach; ATTACH by PID.)
3. Run the correlate capture (scripts in `re/scratch/` of the working machine, copies noted below):
   - `_report_sm3.js` + `_run_report_sm3.py <PID>` — hooks SM3 entry `0xa0748` AND libc `memcpy`
     (filtered size 200–900, first bytes `08 d2 a4` = the report protobuf, only while inside sign
     `0x9ecc0`), then correlates `byteswap(last SM3 state_out)` with the 32B at protobuf tag `9a0120`.
   - Output: the SM3 message whose digest == #19. That message = `query || slot16 || 0x30`.
4. MD-chain reconstruction detail: a new SM3 hash starts when `state_in == SM3 IV`
   (`6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0`, the IV in LE-byte form);
   concat the 64-byte `input` of each block in the chain = the padded message; strip SM3 padding via
   the trailing 8-byte big-endian bitlen.

### Static anchors (base-relative; `.so` is PIC, load at base 0)
- `0xa0748` — SM3 compression fn entry (one 64-byte block per call; state at [x0+8..0x28], input at x1).
- `0xa03ac` — the Merkle–Damgård driver loop caller (`add x19,#0x40; sub w20,#0x40; b 0xa0350`).
- `0x9ecc0` — sign entry `sign(url, cookie) -> headers`.
- `0x1544ec` / `0x14fb30` — the memcpy sites that copy the finished #19 into the report.
- IV constant does NOT appear as a stored literal (computed at runtime) — expected for stock SM3.

---

## 8. FILES TO CARRY OVER

Essential (in `re/huongB_devirt19/`):
- `HANDOFF_hash19.md` (this file)
- `sm3_hash19.py` — offline reference impl
- `_report19_verified.json` — live-verified (message, d19) pairs for the self-test
- `README.md` — full RE history (the `#19 COMPLETELY SOLVED` section at the bottom is current)
- `libmetasec_ov.so` — the exact binary (md5 02f47578)

Capture scripts (were in the working machine's scratchpad — copy if you want to re-capture):
`_report_sm3.js`, `_run_report_sm3.py`, `_fullmsg19.js`, `_run_fullmsg19.py`, `_blockhook_native.js`.

Superseded / DEAD (do not use for offline #19): `_hash19_driver.py`, `_hash19_brute.py`,
`_hash19_solve.py`, `_hash19_reimpl.py`, `_hash19_correct.py`, `modsm3.py`
(the last two encode the WRONG "modified SM3 / T=0" model — stock SM3 is correct).

# END-TO-END run guide — feed device-state → genuine x-argus → server accepts login

**Device bundle:** `7678616678053643790` (install_id `7679520991450973970`, samsung SM-G930F class).
**Goal:** unidbg metasec signer loads THIS genuine device-state → x-argus grows 368→~792 → server
accepts a signed request / login returns **2135 (no `ec7`)** → session.

This bundle carries the **encrypted** mssdk store (`.msdata/mssdk/ov/`). The metasec `.so` on unidbg
decrypts it at runtime — you do **not** decrypt it yourself. The store cipher was cracked
(2026-09-02: `.msp` = RC4(MD5(SHA1(keyname))); see `../../notes/56-...`) which is why we can **verify**
the bundle offline, but the signer needs the *encrypted* files as-is.

Signer machine (Windows) reference from the repo tests: `e:/tiktok_signer/mobile/unidbg`, main class
`tt.Harness`, JDK 21. Adjust paths to your setup.

---

## Step 1 — copy the bundle to the signer machine
Copy the whole folder `msstate_7678616678053643790/` to the Windows box, e.g. `e:/tiktok_signer/state/msstate_7678616678053643790/`.
The signer needs the subtree `.msdata/mssdk/ov/` (the `.msp_*`, `.mss_*`, `.msf3_*`, `.dy/` files).

## Step 2 — verify the bundle is genuine/intact (offline, no signer needed)
```
python3 verify_bundle.py
```
Expect: `[OK] .msp_589… DEVICE-SECRET`, and a printed device-secret with
`kiid=ef86fe33-0264-4b06-ba72-813be3d22158`, `fltk=1787822601249`, `dyn_deviceid=7678616678053643790`,
`dyn_seed(98B, X-Argus #24) = MDGkEprSrHADIDZ6yWtkztTt…`. If it prints that, the store is intact and
will decrypt inside metasec too. (`device_profile.json` mirrors these values, now authoritative.)

## Step 3 — sign a request with THIS device-state fed in
Use the same harness the repo tests use, but point it at THIS bundle and use THIS device's IDs.
Key env (differs from the old `7664922` msstate the repo tests shipped — **use these**):
```
MSB_DEVSTATE_DIR = <...>/msstate_7678616678053643790/.msdata/mssdk/ov
DID              = 7678616678053643790
IID              = 7679520991450973970
MSB_VER          = 45.7.3          # confirm vs the app the bundle was pulled from
MSB_VERCODE      = 2024507030
MSB_FULLINIT=1  MSB_KV=1  MSB_NET=1  MSB_THREADS=1  MSB_THREADS_SECS=12
SIGN=1  FIXTIME=<unix-seconds>  NO_COMPILE=1
```
(Plus the trill vendor/offset env the repo harness already sets: `MS_VENDOR=libs_trill/`,
`MS_LIBS=libs_trill`, `MS_SIGN_OFF=0x9ecc0`, `MS_DISP_OFF=0x11a1e0`, `MS_LICENSE_FILE=…`.)

Write `url.bin` (the request URL) and `cookie.bin` (the signed header block) as the tests do, then run
`java … tt.Harness`. It prints headers between `===SIGN_OUT===` / `===END===`
(X-Gorgon, X-Khronos, X-Ladon, X-Argus). See `tests/t_server_accept.mjs` for the exact wiring —
just swap its `MSB_DEVSTATE_DIR`, `DID`, `IID` to the values above.

## Step 4 — the acceptance signal: x-argus size
- **Forge-only (no device-state):** x-argus ≈ **368 B** (base64 chars ≈ 324–368).
- **Genuine (this device-state fed):** x-argus ≈ **792 B** (base64 chars ≈ 700+).
The +424 B is the device-state block (report #16 device_token ← `rtk2_ms`, #18 uuid16 ← `kiid`,
#24 ← `dyn_seed`). Also expect the unidbg log to show `GET_SEED POST … resp code=200` (metasec built
`get_seed` from the genuine `dyn_seed`). If x-argus stays ~368 or get_seed is absent, the state didn't
load — check `MSB_DEVSTATE_DIR` path + `MSB_KV=1 MSB_FULLINIT=1` and re-run with `MSB_DEVSTATE_VERBOSE=1`.

## Step 5 — server accept / login → 2135
- Quick check (`t_server_accept.mjs` style): POST the freshly-signed feed request → HTTP 200 with a
  real body (not a signature-reject) means the signature is accepted by TikTok's edge.
- Full login (01-PLAN Task 5): drive `src/login.mjs` with headers signed as above for
  `passport/user/login/` → expect **status_code 2135 + aaas_ticket** (NOT `ec7`/device-trust reject).
  If `ec7` persists, diff the request field-by-field vs a genuine `user/login` capture (Task 5 method):
  the remaining gap is a header/body/cookie field, not the signature.

---

## Caveats (must hold for the server to accept)
1. **Device + version must match this bundle.** DID/IID above are for `7678616678053643790`. The device
   fingerprint used at `device_register` (openudid, cdid, serial, build, SM-G930F class) must be the
   profile this device registered with — a mismatch (like the repo's old 7664922-state vs 7632 request)
   makes the result an upper-bound probe, not genuine acceptance.
2. **Rotating fields drift.** `rtk2_ms`, `server_tsp_diff`, counters change over time; the values here are
   the snapshot from extraction (2026-08-31). `dyn_seed` (the x-argus #24 source) is the stable one and
   is verified intact. If the account/device was long dormant, some tokens may be expired server-side.
3. **install_id can rotate** on a fresh activation; if the server rejects IID, re-run device activation
   (NOT full re-register) to refresh IID, keeping device_id.

## What's in this bundle
- `.msdata/mssdk/ov/` — encrypted mssdk store (feed this to the signer).
- `device_profile.json` — authoritative device-secret (re-decrypted from the store 2026-09-02) +
  `slot16_table` (23 endpoints, capture-once) + `settings_counters`.
- `device_secret_plaintext/` — the two decrypted store JSONs (reference).
- `verify_bundle.py` — self-contained offline verifier (run it anywhere with python3).

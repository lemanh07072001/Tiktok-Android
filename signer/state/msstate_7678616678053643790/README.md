# Device-state bundle — device_id 7678616678053643790 (GENUINE, extracted from phone/emulator)

Extracted 2026-08-31 (rooted emulator tt_root, no re-register). This is a COMPLETE
trusted mssdk device-state for feeding the unidbg metasec signer via MSB_DEVSTATE_DIR.

## Identity
- device_id  = 7678616678053643790
- install_id = 7679520991450973970
- (fingerprint: match the profile the device registered with — samsung SM-G930F class)

## Contents
- `.msdata/mssdk/ov/`  — the ENCRYPTED mssdk store (device-secret). The metasec .so
  decrypts these at runtime (device-bound). Key files:
  - `.msp_589c22335a…` = device-secret / PSK  (dyn_seed, rtk2_ms, rdk2_ms, kiid, …)
  - `.msp_092fde7a…`   = settings/counters
  - `.mss_9b8ed99…`    = mssdk_setting
  - `.msf3_*`          = per-key counters (XXTEA, key=MD5(keyname))
  - `.dy/tasks/*`      = dyn task queue
- `device_profile.json` + `device_secret_plaintext/` = the DECRYPTED device-secret
  (for reference / verification; NOT needed by the signer which decrypts itself).

## Decrypted device-secret (.msp_589 = X-Argus report #24 source)
- dyn_seed  = MDGkEprSrHADIDZ6yWtkztTtnLIoFXUlUzcso/xeHUnQLB3XQDc6HAV+FRzlNQOm2ekPLg… (98B, prefix 3031 = X-Argus #24)
- dyn_deviceid = 7678616678053643790
- rdk2_ms   = 7678616678053643790
- rtk2_ms   = 65d4a4323c59fd1a8382a85c0032f95e14a2d0326ddb8f20846d
- rsk2_ms   = 2 ; kiid = ef86fe33-0264-4b06-ba72-813be3d22158 ; fltk = 1787822601249
- dyn_version = 2 ; dyn_last_update_time = 1788177640

## How to feed to the signer (unidbg, e:/tiktok_signer/mobile)
Run the signer with this state so metasec loads the GENUINE dyn_seed → GENUINE x-argus:
```
MSB_DEVSTATE_DIR=<path>/msstate_7678616678053643790/.msdata/mssdk/ov  \
MSB_FULLINIT=1 MSB_KV=1 MSB_NET=1 MSB_THREADS=1 MSB_THREADS_SECS=12   \
DID=7678616678053643790 IID=7679520991450973970                       \
  → collect-thread builds f4 from GENUINE state → get_seed → dyn_seed → x-argus
```
(cf. tests/t_compare_argus_feed.mjs, t_server_accept.mjs which feed msstate this way.)

## Why genuine matters (vs pure-forge)
Note 31: pure-forge x-argus = 368B, genuine = 792B. The 424B gap = device-state fields
(#16 device_token, #18 uuid16, #19 req_hash…). This genuine state supplies them:
kiid→#18, rtk2_ms→#16, dyn_seed→#24. Feeding it should push x-argus 368→792 = genuine,
the material forge-only cannot produce → the path to defeat ec7/device-trust.

## Extraction method (how this was obtained)
spawn-gate + hook 0x10bbd0 (device-secret key-deriv, filter returnAddress==0x1184a8) →
captured x0 = [4B len][zlib(JSON)] BEFORE final encrypt → zlib.decompress → plaintext.
Tools: huongB_devirt19/_mspspawn.js + _spawn_msp.py. Cipher notes: .msf3=XXTEA(_store_xxtea.py).

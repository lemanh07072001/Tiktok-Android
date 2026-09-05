# 63 — #24 (Widevine DUID) INJECTED into genuine X-Argus; two-pass wall SOLVED (Windows)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** title '(Widevine DUID)' **mislabel #24** — theo note 64, #24 = dyn_seed; giá trị inject hiện tại là stub 44-char Widevine, candidate đúng = captured dyn_seed b64 132-char (device_secret_plaintext/). '#16/#18 already appear present' nửa đúng — note 66 field-diff: **#18 present, #16 ABSENT**. Cơ chế two-pass ReadHook (ByteSizeLong + 2 pass serialize đồng thuận, 290→338B, sign exits clean) = emit-path ĐÚNG.

**Status: DONE (mechanism), ground-truth verified.** First device-state field emitted into a clean, genuinely-signed report.

## Result (2026-09-04, Windows d:\Tiktok-Android)
- CLEAN thin report = **290 bytes**; with #24 = **338 bytes** (+48 = one Widevine field).
- Report protobuf @0x12533140 (pre-AES) contains, in-order:
  `... 2080d085c701 | c201 2c 6331704d65556c70…5253413d | c80102 …`
  = f16 | **#24 tag=c201 len=0x2c(44) val="c1pMeUlpZmF4V2VpTlZZbU9SdkJUaXNuZ0JlV0xERSA="** | f25.
- Sign completes: 223750 instrs, exit-PC=0x9f078 (== clean success exit), retptr=0x1256d000 (valid). NO crash.

## Why mode7 crashed and mode10 works (the core insight)
- Serialization is **TWO passes**, back-to-back, on the SAME message object (msg=0xe4ffdd28), both via field-writer 0x153fb0 (FWCOUNT: f23=2). There is NO message-copy wall between them.
- BUT a **separate ByteSizeLong** runs BEFORE serialize and caches the report size. It does NOT go through 0x153fb0. It reads #24 member slot **0xe4ffde10**; if that slot = proto3 default char* `0x12196e5a` at size-time, cached size EXCLUDES #24.
- mode7/mode9 set the member at the f23-**writer** (serialize-time) = too late → serialize writes +47 bytes the buffer wasn't sized for → heap overflow → crash (PC→0x1000).
- **FIX (mode10 / MSB_M24READ):** a unidbg **ReadHook on 0xe4ffde10** forces the slot = persistent char* on every guest read, so ByteSizeLong (size) AND both serialize passes agree → buffer sized WITH #24 → clean.
- Must **stop forcing once AES starts** (flag `aesStarted[0]` set at 0x159d70). The 0xe4ffxxxx region is reused for AES/output state post-serialize; forcing into it there corrupts output → tail crash at 0x173ef8. Gating on aesStarted fixed it.

## The repeatable recipe (per field)
1. Collect the field VALUE via its natural collect-route into scratch (e.g. #24: drive 0x122b90 w/ MediaDrm JNI → base64-DUID into [0x1fbe00]).
2. **Capture** it to a PERSISTENT malloc (survives sign scratch reuse) → `wvStr[0]`. (Dump.java, post-collect block.)
3. **ReadHook-force** the field's member slot → persistent ptr, gated `signPhase && !aesStarted`.
4. Verify: report grows by field size, `tagXX len val` present pre-AES, sign exit-PC == clean.

## Run recipe (Windows)
```
export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot"
cd signer
SIGN=1 FIXTIME=1788501126 MSB_WIDEVINE=1 MSB_M24READ=1 \
  ./tools/gradle/bin/gradle dump --console=plain -DWV_DRIVER=1
# optional: MSB_FWLIVE=1 (watch f22..26 writer), -DM24ADDR=0x... (slot addr), -DRPTHEX=340
```

## OPEN (not solved by this)
- **VALUE is a STUB.** #24 here = base64 of MediaDrm stub DUID "sZLyIifaxWeiNVYmORvBTisngBeWLDE ". A server that validates Widevine content would want the REAL provisioned DUID. Genuine DUID may be extractable from `signer/state/msstate_7678616678053643790` (98M real bundle) — TODO diff.
- **Server content-validation UNTESTED** (still blocked on credentials). Whether full-772 is *accepted* vs thin remains unproven; this note proves only that we can *build* it structurally.
- Remaining device-state fields (#5/#8/#17 and any others short of genuine 772) need the same recipe; #16/#18 already appear present in thin dump — re-diff vs genuine before assuming missing.

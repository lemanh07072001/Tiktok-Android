# Note 62 — Windows toolchain stood up + collect-route #24 value SOLVED (wire remains)

> ⚠️ **ĐÍNH CHÍNH (audit 2026-09-04):** (1) Title 'collect-route #24 value SOLVED' **sai** — nó solve một Widevine DUID KHÔNG PHẢI #24 (note 64: #24 = dyn_seed); DUID chỉ là stub value. (2) 'remaining wall: localize singleton read-slot' ĐÃ ĐƯỢC GIẢI bởi note 63 (mode10 MSB_M24READ two-pass ReadHook). Phần toolchain/recipe/run-vars vẫn là nền cho 63/65 (box mất là e:/tiktok_signer/, không phải máy này).

> Decision path (2026-09-04): A (copy Windows Harness) = IMPOSSIBLE (original signer box `e:/tiktok_signer/` gone).
> User chose C→B: build full-772 by hand-injection, ON THIS WINDOWS MACHINE.

## Phase 0 — toolchain on Windows: DONE ✅ (was the #1 risk, now eliminated)
- Installed Temurin JDK21 (winget `EclipseAdoptium.Temurin.21.JDK` 21.0.12). No JDK/gradle/m2 existed here.
- Bundled gradle `signer/tools/gradle` (8.10.2) runs under JDK21; pulls `unidbg-android:0.9.9` from Maven.
- `tt.LoadTest` smoke: `[OK] base=0x12000000, 147 init ctors ran`; **`[SUCCESS] JNI_OnLoad completed`** — the
  anti-tamper svc handler + JNI env + RegisterNatives all run IDENTICALLY on Windows (unidbg pure-Java). Hit the
  expected config-globals-empty wall (MSManager.init, notes/57 §10-11) — same as Mac.
- `tt.Dump` real sign (`SIGN=1`): emits real **X-Argus / X-Gorgon / X-Khronos / X-Ladon** from (url.bin, cookie.bin)
  + device-state, 220311 instrs, exit-PC 0x9f078. THIN (register/consent report, no device-state fields). = Mac behavior.
- Run recipe (Windows):
  ```
  export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-21.0.12.101-hotspot"
  cd signer && SIGN=1 FIXTIME=1788501126 [MSB_*] ./tools/gradle/bin/gradle dump --console=plain [-DWV_*]
  ```
- build.gradle `dump` task patched to forward `-DWV_* -DINJ24* -DRPTSCAN* -DOFF24 -DWADDR` to the forked JVM
  (previously only env vars + a few fixed props reached tt.Dump).

## Phase 1 — re-derived on Windows (Mac addresses do NOT transfer)
- Report BUFFER base (heap, host-variable): Mac 0x12555000 → **Windows 0x1251e200**. Added `MSB_RPTSCAN` probe
  (auto-detects base: logs every 0x154f7c walker emit dst/len/bytes). Each field emitted **twice** = two-pass
  (ByteSizeLong + Serialize) CONFIRMED. #24 (proto tag `c2 01`) **absent** from emit stream = skipped-empty. #25 (`c8 01`) present.
- Message OBJECT region `0xe4ffxxxx` IS stable across Mac/Win (rptSelf 0x95a3c = 0xe4ffee10 both). But the fine-grained
  #24 member addr / PCs / sentinels from note 60 (WADDR 0xe4ffde10, PC 0x3d1990, 0x12196e5a/0x12517680) are that-run-specific
  and no longer map — WHOOK on 0xe4ffde10 shows a different std::string now. **All note-60 INJ24 modes must be re-derived here.**

## ★ #24 VALUE obtained naturally (collect-thread route WORKS on Windows)
`MSB_WIDEVINE=1 -DWV_DRIVER=1` drives collect+store `0x122b90`:
- MediaDrm JNI fully served: FindClass(android/media/MediaDrm)+UUID(0xedef8ba979d64ace,0xa3c827dcd51d21ed) → NewObject →
  `getPropertyByteArray("deviceUniqueId")` → captured DUID "sZLyIifaxWeiNVYmORvBTisngBeWLDE " (32B) → release.
- `[WIDEVINE driver 0x122b90] 4595 instrs ret=0x0 reachedMediaDrm=true`
- **`[0x1fbe00] after = c1pMeUlpZmF4V2VpTlZZbU9SdkJUaXNuZ0JlV0xERSA=`** = base64(DUID), std::string{cap45,len44,ptr}.
  ⇒ the #24 *value* is producible on demand (no fabrication) — solves note-60's "serve MediaDrm + run collect".

## The remaining wall (precise): report-builder does NOT read #24 from [0x1fbe00]
- Ran collect THEN sign: report STILL has no #24 (c201 absent), X-Argus still thin. So [0x1fbe00] is our scratch,
  NOT the device-state singleton slot the report-builder reads #24 from. (Real flow: collect runs on an indirect
  thread → stores #24 into a singleton → report reads singleton. unidbg skips the thread; our manual 0x122b90
  stored to scratch instead of the singleton.)
- **NEXT (the one hard RE step):** find the object+offset the report-builder reads #24's std::string from during
  sign (the read that returns len=0 right before the #25 emit), then write the collected base64-DUID std::string
  there BEFORE the ByteSizeLong pass (so size+serialize are consistent — avoids the two-pass buffer-overflow that
  killed the mode7 serialize-only injection). This is the singleton-slot localization, replacing the message-copy hunt.
- VALUE still UNPROVEN: no tested endpoint validates x-argus CONTENT (notes/58,60). Finishing #24 is 1 of ~5 missing
  fields (#16/#18/#19-slot16/#5/#8/#17). Recommend a content-validation test (login/ec7) in parallel before deep grind.

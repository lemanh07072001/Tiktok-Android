# Note 60 — Full-772 attestation build (make tt.Dump emit missing device-state fields)

> User goal (2026-09-03): tt.Dump ra x-argus THIN (register 324B / consent 290B) — thiếu device-state.
> Genuine phone = 772B. Điền các field thiếu để device register/login TRUSTED.
> Gap = **full-init harness** (STATUS nhiều lần: multi-week). Note này = field-map + approach + tiến độ.

## Report field gap (parsed từ tt.Dump reports)
| field | consent(290B) | register(324B) | nguồn | approach |
|---|---|---|---|---|
| #18 uuid16 | ✅ | ❌ | attestation, pskVersion="0" | device provision; register device_id=0→pskVer "none" (fresh legit thin?) |
| #19 pskCalHash | ✅ | ❌ | SM3(query‖slot16‖0x30) | slot16 device-stable capture-once (0xa0748) |
| #24 Widevine | ❌ | ❌ | collect-thread MediaDrm | **serve MediaDrm JNI + call thread-entry 0x122b00** |
| #16 device_token | ❌ | ❌ | ←rtk2_ms (trong .msp store, ĐÃ decrypt) | inject/populate từ device-secret |
| #5/#8/#17 | ❌ | ❌ | identity (device_id/sdk-ver/ts) | populate device-state config |
| #32/#34-36 | ✅ | ✅ | sig | có sẵn |

## #24 Widevine — call-chain MAPPED
- collect body `0x12305c` (UUID Widevine hi=0xedef8ba979d64ace lo=0xa3c827dcd51d21ed @0x1231b8 → bl 0x13d328 MediaDrm helper ×2 @0x1231e4/0x1232cc).
- `0x13d328` = MediaDrm JNI helper (FindClass android/media/MediaDrm + java/util/UUID, NewObject, getPropertyByteArray("deviceUniqueId") → deviceUniqueId, ExceptionCheck/Clear/DeleteLocalRef).
- **Thread-entry = `0x122b00`** (calls collect 0x12305c via 0x122d78; 0x122b00 has NO BL callers = indirect thread dispatch → unidbg doesn't run it → #24 absent).
- captured deviceUniqueId = "sZLyIifaxWeiNVYmORvBTisngBeWLDE" (735a4c79...).
- **PLAN**: Dump.java → (1) AbstractJni serve MediaDrm/UUID JNI returning captured deviceUniqueId; (2) after init, callFunction(0x122b00, ctx) to run collect → #24 into device-state; (3) sign → verify #24 in report.
- RISK: 0x122b00 needs thread-arg/ctx; metasec fns in isolation have looped before (config-setter). Empirical test needed.

## Honest scope: full-772 = multi-session harness (Widevine collect + provision get_seed→#18/#19 + slot16 capture-once + identity populate). Each field a sub-build. Start = #24 (most defined, universal gap).

## Progress
- [2026-09-03] Field-map done. #24 call-chain + thread-entry 0x122b00 localized. NEXT: wire MediaDrm JNI + call 0x122b00 in Dump.java.

## #24 — reconciled with note 46 (collect-thread CRASH wall, empirical 2026-08-25)
- 0x122b00 (lazy-singleton getter) called in tt.Dump → 174 instrs, returns singleton 0x12519460, **0 MediaDrm**. Matches note 46: collect-thread doesn't emulate cleanly (crashes before MediaDrm: JNI GetVersion stub + unmapped mem + thread-stack).
- Windows Harness.java HAD full MediaDrm stub (lines 1296-1360: new MediaDrm(UUID)→obj, getPropertyByteArray→env MSB_DUID synthetic; init-bypass MSB_INITFLAG/FAKESTATE/THREADS) — STILL crashed → 0 MediaDrm, #24 absent. tt.Dump (Mac) doesn't even have the stub yet.
- **KEY (note 24 W1)**: server does NOT cross-check #24 with Google — only needs #24 consistent with device_id ⇒ **synthetic DUID may pass (UNTESTED)**.
- ⇒ **#24 pure-offline = collect-thread frontier (multi-week, crash-wall)**. Pragmatic = mint-once (extract #24/device_token/uuid16 from phone 1×, feed static) OR device-state injection (find #24 source slot, write synthetic — needs slot RE).

## ★ HONEST VERDICT on full-772 (all fields)
- **Pure-offline no-phone full-772 = multi-week frontier** (collect-thread emulate for #24 + provisioning for #18/#19 + slot16 capture + identity). Confirmed by notes 30/46/58/59 convergence.
- **BUT full-772 may be UNNEEDED**: register (324B thin) → new_user=1 SUCCESS; T10 (290B thin) → server accepts API call. Both empirical this session. The decisive check = does the thin-registered device LOGIN (2135 vs ec7).
- **Pragmatic full-772 = mint-once** (1 phone touch → extract device-stable attestation → feed static → tt.Dump emits full-772 forever).
- Dump.java: added MSB_WIDEVINE=1 diagnostic (calls collect getter 0x122b00) — confirms 0-MediaDrm path.

## Progress: full-772 pure-offline = multi-week (collect-thread frontier for #24, provisioning for #18/#19). Recommend: (a) verify need via login test, OR (b) mint-once, OR (c) commit to multi-week collect-thread emulation fix.

## ★★★★ #24 WIDEVINE COLLECT RUNS IN tt.Dump — PAST note-46 WALL (2026-09-04)
> note 46 (Windows Harness): collect-thread CRASHED before MediaDrm. NOW: collect runs to completion + retrieves deviceUniqueId in tt.Dump (Mac). Breakthrough.

### How (Dump.java MSB_WIDEVINE=1 -DWV_COLLECT=1 -DWV_ARG=1):
1. **Call collect body 0x12305c directly with x0=JNIEnv** (envP=vm.getJNIEnv()). KEY: collect's first arg = JNIEnv (x19=x0 used as env for all JNI). Passing the manager (0x122b00 result) was WRONG → env-null crashes.
2. **Seed TLS[tpidr+0x28]=envP** (some helpers read env from TLS).
3. **Serve MediaDrm JNI in AbstractJni**: newObjectV(java/util/UUID(JJ)) + newObjectV(android/media/MediaDrm(UUID)); getStaticObjectField(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)="deviceUniqueId"; callObjectMethodV(getPropertyByteArray)→MSB_DUID (default "sZLyIifaxWeiNVYmORvBTisngBeWLDE"=735a4c79..., captured genuine).
4. Result: collect 3471 instrs, NO crash, **getPropertyByteArray returns DUID to SDK** (log: `CallObjectMethodV(MediaDrm, getPropertyByteArray("deviceUniqueId") => [B@0x735a4c79...)`).

### REMAINING for #24 (well-defined, smaller):
- collect(x0=env, **x8=out-buffer sret**) writes #24 to out-buffer; the CALLER path in 0x122b00 (after 0x122d78: `bl 0x15009c` @0x122d8c) stores it into device-state global **[0x1fbe00]** (adrp x20,#0x1fb000; add #0xe00). Calling collect in isolation retrieves DUID but doesn't store → #24 absent in report.
- NEXT: either (a) set x8=scratch before collect, read #24 out, manually store into [0x1fbe00] (need 0x15009c std::string format); OR (b) drive 0x122b00's full collect+store path (gates: flag [0x1fc210], check 0x172580, counter [0x1fbe04]<=3) so it stores #24 itself; then verify #24 in sign report.
- Env-helper cluster patched (29 fns 0x13b000-0x13e000, x0=envP) as backup — but env-as-x0 (WV_ARG=1) is the clean fix (no crash).

## STATUS: #24 collect-thread wall (note 46) BROKEN — DUID retrieved in tt.Dump. Remaining = store #24 into [0x1fbe00] device-state. Then #18/#19/slot16/identity (3 fronts). (C) progressing.

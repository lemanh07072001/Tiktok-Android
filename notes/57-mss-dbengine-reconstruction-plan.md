# 57 — .mss DB-engine reconstruction (MULTI-SESSION plan)

**Goal:** get the .so's own store/DB engine to LOAD + DECRYPT `.mss` (mssdk_setting, 630B) inside
our Unicorn emulation, then dump the decrypted in-memory map = plaintext settings.
**Chosen path:** drive the real engine (build/construct the object graph so its own code runs) —
NOT hand-reverse the DB serialization format.
**Value caveat (recorded):** `.mss` static-decrypt is NOT needed for the offline SIGNER (the real
.so under unidbg reads the raw store files itself; see memory [[signer-mss-not-needed]]). This is an
analysis/completeness effort the user explicitly chose. Device-secret `.msp` = DONE (crown jewel).

## Infrastructure READY (this session — logger wall broken)
`huongB_devirt19/_mss_getter2.py` = Unicorn harness that already clears the blockers:
- stateful pthread TLS (getspecific/setspecific/once/key_create)
- lazy logger singleton bypass (pre-seed sink `*(0x1efbd8)` self-ref + bypass vtable calls 0x13b010/0x13b034)
- syscall VFS (openat/read/lseek/fstat st_size@0x30/close/mmap serve file bytes)
- null-blr auto-skip (diagnostic) — runs store fns to clean return.
Also: `_mss_emu.py` (faithful AES-256-ECB oracle for 0x10c158), `_mss_load.py` (accessor drive + mem-scan).

## OBJECT-GRAPH MODEL (mapped so far — verify each before relying)
- **Store object = a hash-map container**; ctor `0x68b68(obj, initBuckets)` allocates 0x50-byte buckets,
  fields: self@0, size@0x10, buckets@0x18/0x20/0x28, + std::mutex. (28 callers → many stores.)
- **Store map lives INLINE at `ctx+0x128`**: `0x65a7c(ctx)` = `add x0,#0x128; ret`.
- **value-GET `0x118e54(store, keyname, out, mode)`** = mutex-lock → `0x118980`(map lookup, in-memory) →
  copy value to `out`. **NO file I/O, NO decrypt** — pure in-memory query. (14 callers.)
- **map-lookup `0x118980`** (4 callers = the get/set family 0x118d88/0x118e14/0x118e8c/0x118f24).
- **mssdk_setting accessor `0x6bb84`** (callers: `0x5f3ac`, `0x67f5c`): store=`0x65a7c(x19=ctx)`; reads
  numeric settings via `0x118e54(store,"st1"/"st2"/"st3"/…@0x17c660,out,1)` → ucvtf/fcmp (float configs).
  Emulated end-to-end → clean return but **opens NO file** ⇒ map not populated ⇒ returns defaults.
- **Store-file WRITER = `0x12f290`** (fopen 0x16facc + 3× fwrite 0x171c58 `[8Blen][8Bfield][data]` + fclose).
- **Store-file read-I/O `0x12e79c`** (fopen + fread 0x171d70), unified R/W by mode arg w3.
- **Item-decrypt `0x10e224`** (called 0x13ac3c item-reader, 0x12fce0, 0x11917c): `decrypt(out, unhex(ct), key=MD5(itemkey))`.
- **File-layer crypt (writer kind-dispatch 0x1182d0):** kind0=0x10bbd0 RC4(.msp), kind1=0x10c158 AES-256-ECB(.mss), kind2=0x10dce0 XXTEA(.msf3).

## THE MISSING PIECE = the LOADER
Nothing found yet reads `.mss` into the `ctx+0x128` map. The map is populated at **context construction /
SDK init** (eager), then accessors query it. Find the function that: opens the store file → decrypts →
parses entries → inserts into the map. It is tied to the context (x19) lifecycle.

## STEP LADDER (each step = a session-sized chunk; verify with emulation)
1. **[DONE]** Break logger wall + build VFS harness (`_mss_getter2.py`). Confirm store fns run to clean return.
2. **[DONE]** Map object graph: store=hashmap@ctx+0x128, value-GET 0x118e54→0x118980 (in-mem), accessor 0x6bb84.
3. **[PARTIAL] Find the LOADER.** Accessor caller `0x67ee8`: `ctx x19 = [arg0+8]`; x19 already holds the
   store map@+0x128 (queried by accessor) AND a loaded-stores list@`x19+0x160` (iterated, vtable[0x18] each).
   ⇒ the store map is populated at **x19 (context) CONSTRUCTION during SDK init**, before any accessor.
   **NEXT: locate x19's constructor / the SDK-init store-load** (who builds [arg0+8] and fills +0x128 from disk).
   Candidate fopen-callers still to check: 0xbd600/0x10b3f0/0x11e1cc/0x124fec/0x162e94. Deliverable: loader addr +
   (ctx,filename) ABI + file-layer decrypt used. Then emulate it (step 4) with VFS serving .mss.
4. **Emulate the LOADER** with VFS serving `.mss` + a constructed/kept context. It should read+decrypt+populate.
   Watch VFS `opens` to confirm it reads the file; watch heap for inserted plaintext entries.
5. **Construct the context** if step 4 needs it: run the store-manager/context constructor(s) in-emulator
   (0x68b68 map ctor + whatever builds ctx), so vtables/fields are real (fixes null-blr skips).
6. **Dump plaintext**: after loader runs, walk the `ctx+0x128` hashmap (buckets@0x18) and read key→value
   MSStrings = the decrypted mssdk_setting settings. Verify keys look sane (st1/st2/st3/... + values).
7. **Generalize**: same harness reads st1/st2/st3/bootsoft stores. Optionally port to a standalone decryptor.

## Gotchas / notes
- MSString custom layout `{u32 cap@0, u32 len@4, ptr data@8}` (NOT libc++). read via _mss_emu helpers.
- Anti-tamper inlined `svc` (dynamic-nr) — VFS handler in _mss_getter2 covers the common ones.
- If loader needs the store-manager singleton (0x1f4130, vtable *(0x1d9d98), ctor 0x68b68 via 0x6bf7c), construct it.
- venv `~/.re-venv` (unicorn 2.1.4). Run from `huongB_devirt19/`.
- See note 56 §12–14 for the full derivation; memory [[msp-cipher-xorstream-vm-gated]] [[store-cipher-is-standard-aes]].


## SESSION 2 progress (2026-09-03) — loader chain found; getters iterate EMPTY intermediates (load is upstream at SDK-init)
- **Loader chain (device-secret store, validatable):** getter `0x1185d0` (lazy, guard *(0x1fb960), store singleton @0x1fb910)
  → `0x117e14(store,name)` → **worker `0x52924`** (CFF) + callback `0x1188e0` (populate map).
- **Allocator fptr fix (now baked into `_mss_getter2.py`):** SDK indirect alloc table `*(0x1f3bc8)/bd0/bd8` (set lazily at
  0x17515c from GOT *(0x1ef608/580/7d8), NULL after init_array) → pre-seed to PLT malloc/free/realloc. Was causing the
  file-read/alloc `blr *(0x1f3bc8)` (@0x1771b0) to be a null-blr → alloc fail → load abort.
- **Emulated `0x1185d0` (VFS=.msp_589): reaches worker 0x52924 but callback 0x1188e0 NEVER fires, opens=[]** ⇒ worker
  iterates an EMPTY in-memory source. ⇒ **the file read+decrypt is UPSTREAM at SDK-init** (populates an intermediate
  collection that the getters iterate); getters themselves do NOT touch disk.
- **Refined blocker / NEXT (session 3):** find the SDK-init function that OPENS the store files (fopen candidates
  0xbd600/0x10b3f0/0x11e1cc/0x124fec/0x162e94) + reads+decrypts them into the intermediate. Run THAT in emulation
  (VFS serving the file) to populate, then the getter/worker will emit entries. Validate on device-secret (.msp_589,
  known plaintext kiid/dyn_seed) BEFORE mssdk_setting.
- **Honest trajectory:** DB-engine is CFF + eager-init + multi-layer; each session peels one layer. Plaintext needs
  running SDK-init-level file readers. Several more sessions. (.mss value for SIGNER = 0; this is analysis, user's choice.)

## SESSION 3 progress (2026-09-03) — file-readers ruled out; store I/O is SDK-init inlined-svc (static path = multi-day slog)
- Checked all standard `fopen` callers. `0x124f58` = `/proc`-style TEXT reader (snprintf path→fopen→**fgets loop**→
  line-match 0x172248) = anti-tamper/env check, NOT a store reader. Others similar. ⇒ store files are NOT read via
  these fopen sites.
- Worker `0x52924` makes **0 syscalls** in the getter path (iterates in-memory), arg `x0=0x1909b0` = a CFF jump-table
  (binary, not fmt). The store map is populated at **SDK-init** through the anti-tamper **inlined-svc** file I/O
  (`0x12e79c`→`0x16facc` = the .so's OWN fopen doing inlined openat svc; our VFS DOES intercept those svc), then
  getters iterate the map. Reaching it = running the SDK-init store-load (CFF, entangled).
- **STRATEGIC FINDING (important):** the FAST way to get `.mss` plaintext is NOT static reconstruction — it is to hook
  the real .so's store getter `0x118e54` (or dump the ctx map) AFTER the real .so loads the stores, i.e. inside the
  **offline SIGNER / unidbg runtime** (which feeds the raw store files and lets the real .so decrypt them). That path
  ALSO delivers the project goal (offline signing). The static DB-engine drive is a multi-day CFF slog with ZERO
  signing value. RECOMMENDATION: pivot to the signer runtime (port the svc-handler from Windows, `signer/COPY-FROM-WINDOWS.md`),
  then hook `0x118e54` → get all mssdk_setting values for free. See [[signer-mss-not-needed]].

## SESSION 4 (2026-09-03) — store READER localized; PROVEN CONVERGENCE: static needs the SDK-init context (= runtime)
- **Store-file READER = `0xb0d10(x0=ctx, x1=keyname[, x8=out])`** (contains the 0x12e79c read @0xb13ac; `cbz x1` needs keyname).
  Immediately preceding it: the **store-manager singleton `0x1f4130`** is constructed (vtable `0x1d9d98`, ctor `0x68b68(obj,2)`, __cxa_atexit).
- **Emulated `0xb0d10` on sdi_v2/.msp_092 (KNOWN RC4 plaintext) AND mssdk_setting/.mss with a scratch ctx (x0):**
  BOTH → `opens=[]`, `out=0B`, pc=RET. The reader **bails before any file I/O** because x0 (context) is empty — it
  checks context fields (store-manager ptr, dir path, intermediate) that a zeroed scratch lacks.
- **PROVEN across sessions 2-4:** getter `0x1185d0`, loader `0x117e14`/`0x52924`, reader `0xb0d10` ALL require the
  SDK-init-constructed context. With scratch context each returns empty and touches no file. Building that context
  piecemeal is intractable (each fn checks different fields); building it properly = running SDK init = needs a full
  JNIEnv + trips anti-tamper = **the full runtime**. ⇒ the static-emulation path CONVERGES on requiring the runtime.
- **What the 4 sessions DID deliver (reusable, makes runtime-hook trivial):** logger-wall-broken emulation harness
  (`_mss_getter2.py`), allocator-fptr fix, and the exact addresses — store-value GET `0x118e54`, map-lookup `0x118980`,
  reader `0xb0d10`, loader `0x117e14`/worker `0x52924`, store objects `0x1fb910`(device-secret)/`0x1f4130`(store-mgr),
  accessor `0x6bb84`(mssdk_setting). In a WORKING runtime (signer/unidbg or Frida on device), hooking `0x118e54` or
  dumping the `0x1f4130`/ctx+0x128 map after load yields ALL mssdk_setting values with ZERO further RE.
- **CONCLUSION:** to get `.mss` plaintext, the runtime is required either way. Recommend using the mapped addresses to
  hook the store getter in the offline SIGNER (once its svc-handler is ported) — delivers `.mss` AND the signing goal.

## SESSION 5 (2026-09-03) — ★ BREAKTHROUGH: unidbg RUNTIME decrypts stores; device-secret VALIDATED
**Pivoted to the working unidbg runtime** (signer/, `tools/gradle/bin/gradle -q dump` runs `tt.Dump`). The .so
fully initializes on Mac (JNI_OnLoad completes: GOT-stub 37 libc++ imports, GetSuperClass=null). Store-load now WORKS:
- **MS.b Jni callback** must be implemented (native↔Java dispatcher `MS.b(IIJLjava/lang/String;Ljava/lang/Object;)`).
  Stubbing it (return null) is enough for the store getter to proceed.
- **IOResolver** serves the raw store files (.msp_/.mss_/.msf3_) from `signer/state/.../.msdata/mssdk/ov/` by basename.
- **Device-secret store getter `0x1185d0`** (self-contained singleton @base+0x1fb910): call it → it reads `.msp_589`
  (served) → decrypts → populates the map.
- **Value-GET `0x117e94(x0=store, x1=keyname_cppstr, x8=out)`**: set x8 via an entry breakpoint, then
  `mod.callFunction(emu, 0x117e94, store, keynamePtr)`; read `out` as a C++ string. keyname = libc++ std::string
  `{cap=(len<<1)@0, dataptr@8}` (short form) — mkCpp in Dump.java.
- **VALIDATED vs known plaintext:** kiid=`ef86fe33-0264-4b06-ba72-813be3d22158`, dyn_deviceid=`7678616678053643790`,
  fltk=`1787822601249` — EXACT match. Plus rtk2_ms, dyn_seed decrypted. ⇒ runtime store-decrypt is byte-correct.
- **`.mss` (mssdk_setting) remaining:** its accessor `0x6bb84(ctx)` needs the REAL SDK ctx (crashes with a malloc'd
  scratch ctx — same as the Unicorn attempts). `0x1185d0`'s loader `0x117e14` is device-secret-only (1 caller).
  NEXT: find the mssdk_setting store's self-contained getter (lazy singleton in 0x1fbXXX like 0x1185d0) OR obtain the
  real ctx (from the store-manager singleton 0x1f4130 / MS object), then read its keys (st1/st2/st3/...) via 0x117e94.
- **Deliverable:** `signer/src/main/java/tt/Dump.java` (+ gradle `dump` task). NOTE: signer/ is contested — a parallel
  process edits LoadTest.java; Dump.java is the independent .mss harness.
- **This also de-risks the SIGNER:** MS.b callback + IOResolver + the running runtime are exactly what the sign path needs.

## SESSION 5 cont. — mssdk_setting gated on SDK live-context (sign path); device-secret store = separate & DONE
- Confirmed device-secret store (0x1fb910) does NOT hold st1/st2/st3 (mssdk_setting keys) — separate store.
  (Note: string-getter 0x117e94 returns "" for integer-valued device keys like dyn_version/rep_vd — those need a getInt variant.)
- mssdk_setting accessor chain: `0x6bb84(ctx)` ← wrapper `0x5f3a4(x0=ctx)` and `0x67ee8` (ctx=[arg0+8]). `0x67ee8` has
  NO direct bl callers ⇒ it's a native entry reached from Java (name-mangled) / vtable, using the SDK's LIVE context.
  JNI_OnLoad shows no RegisterNatives in unidbg log ⇒ methods resolved by mangling / called as direct native fns
  (like sign dispatch 0x11a1e0). ⇒ **mssdk_setting load is triggered by invoking an MS native entry with the live ctx**
  — i.e. the SIGN path (the parallel cmd-sweep work). No self-contained mssdk getter exists (unlike device-secret).
- **STATE:** runtime store-decrypt VALIDATED (device-secret exact). mssdk_setting plaintext NOT yet obtained — gated on
  a working native-method/sign invocation that populates the SDK context + loads .mss. Once ANY such call runs, the
  Dump.java hook on 0x118e54 (store GET) captures st1/st2/st3 = mssdk_setting values, for free.
- **NEXT:** (a) get a settings-triggering MS native call working (converges with sign-ABI RE: 0x11a1e0/0x9ecc0), OR
  (b) construct the SDK context (store-manager singleton 0x1f4130 + fields) so accessor 0x6bb84 runs. Both非-trivial;
  (a) doubles as the signer goal.

## SESSION 5 final — sign path reached but bails (CFF); mssdk_setting gated on it
- unidbg store-read VALIDATED (device-secret kiid/dyn_deviceid EXACT). Deliverable `signer/tt.Dump` proven.
- Value-GET mechanics in unidbg: use a **CodeHook** at 0x117e94 (NOT dbg.addBreakPoint — that breaks INTO the debugger
  and stalls non-interactive runs). CodeHook can reg_write x8 (sret) or log keyname (x1). readCpp handles libc++ short-string.
- **SIGN dispatch `0x11a1e0` traced:** with args (env, ms, 1, 0, 0, url, 0) → prologue drops x0/x1(env/this), real args =
  (w2,w3,x4,x5,x6). Runs **2356 instrs, returns at 0x11a270** via `bl 0x11a390`, WITHOUT reaching settings-read 0x117e94.
  ⇒ bails early (matches parallel cmd-sweep). `0x11a390` + `0x11a1e0` are CFF-flattened (trampoline `br x0+0x38`,
  inlined `svc #0`, opaque dispatch) — the whole sign subsystem is OLLVM-VM. Making sign do real work = deep CFF RE
  (correct method ABI + SDK init sequence) = the parallel sign track.
- **mssdk_setting is gated on the sign/settings path reading 0x117e94 with a live ctx.** The Dump.java hook already
  logs `[SIGN reads setting] key=...` — the moment a correct sign/init call reaches 0x117e94, st1/st2/st3 are captured.
- **HONEST STATE:** runtime store-decrypt = DONE+validated. mssdk_setting plaintext = blocked on the CFF sign-ABI
  (parallel work). No further static/runtime shortcut found; the sign call must be made to progress past 0x11a270.

## SESSION 5 — sign-ABI push result: both entries are OLLVM-CFF-VM, bail without SDK-init state
- **Sign call bl-trace:** `0x11a1e0(env,ms,cmd,...)` runs 2356 instrs but ALL calls are CFF trampolines
  (`0x11a224/0x11a3f8/0x11a45c` = tiny "return [sp+8]"; `br x0+0x38`) — NO real work fn, returns at 0x11a270.
  Varying cmd (sweep 0-80) doesn't change the path ⇒ VM branches on GLOBAL INIT STATE, not the arg.
- **`0x9ecc0` (MS_SIGN_OFF)** = also CFF-VM: guard `*(0x1f4a08)` lazy-init (config `0x1f49f0` via 0x5ed34) then
  trampoline dispatch `br x0+0x38`. Takes (x0,x1)=data. Same VM structure.
- ⇒ the sign subsystem is OLLVM-VM; it needs the SDK **init state** (globals `0x1f4a08`/`0x1fbad0`/store-mgr `0x1f4130`)
  set by an init sequence before it does real work. The init is where the accessor `0x6bb84` gets its real ctx AND
  where mssdk_setting config is read. Finding+running that init (or devirting the VM) = deep OLLVM RE = the parallel sign track.
- **CONCLUSION:** mssdk_setting plaintext is gated on the SDK-init/sign VM doing real work. My Dump.java runtime +
  `[SIGN reads setting]` hook will capture st1/st2/st3 the instant that init/sign reaches value-GET 0x117e94.
  The validated store-read runtime is the concrete deliverable; the sign/init VM devirt is the remaining (parallel) work.

## SESSION 5 — sign VM: single native entry mapped; uniform bail regardless of ALL args (hard VM wall)
- **RegisterNatives registers EXACTLY ONE native** (call @0x119f10, count=1): `methods={name, sig, fn=0x11a1e0}`.
  So the whole SDK is driven through `MS.b(int,int,long,String,Object)` → native `0x11a1e0` (JNI static; prologue drops
  env/this, real args = int a=w2, int b=w3, long c=x4, String d=x5, Object e=x6). First int = command.
- **Exhaustive test:** cmd ∈ {1..6,8,16,32} × non-null Object(byte[]) × url → **ALL give the identical 2356-instr path,
  return at 0x11a270**, call-seq = only CFF trampolines (0x11a224/0x11a390/0x11a3f8/0x11a45c). Args make ZERO
  difference; no svc hit; never reaches settings-read 0x117e94. ⇒ the VM runs a FIXED program that exits early
  irrespective of input — a genuine OLLVM-VM wall. Matches the parallel LoadTest sweep (2356 uniform).
- **CONCLUSION (firm):** the sign entry + ABI are now fully mapped (0x11a1e0, MS.b sig, arg layout). But making the VM
  do real work requires DEVIRTUALIZING the VM (its bytecode program + the missing precondition/init-state that gates
  the sign path) — a multi-day OLLVM effort, identical to what the parallel sign track (LoadTest) is doing. Incremental
  arg/cmd probing is exhausted (re-confirms the same 2356 bail).
- **mssdk_setting** stays gated on this VM reaching 0x117e94. Dump.java `[SIGN reads setting]` hook is armed to capture
  it the instant the VM progresses. RECOMMENDATION: converge with the sign track's VM-devirt rather than duplicate it.

## SESSION 5 — sign VM structure devirt (partial): OLLVM threaded-code + decoys + internal loop
- **0x11a1e0 = thin wrapper** → tail-calls VM body **0x11a390**.
- **Threaded-code CFF**: each block ends `bl <tramp>; add xN,x0,#const; br xN`. The tramp (0x11a224/0x11a3f8/0x11a45c)
  returns `[sp+8]` = the addr right after the bl; `+const` (0x38/0x34/0x8) picks the next block. ⇒ control flow is
  effectively STATIC (deterministic block chain), just obfuscated — NOT data-dispatched at these edges.
- **Decoy anti-tamper**: block 0x11a494 does `mrs NZCV; mov x0,#0; cmp; msr NZCV,x0; b.ne` (always taken) skipping a
  `clrex; brk #0x3`. Inlined `svc #0` at 0x11a248/0x11a41c sit in blocks the chain JUMPS OVER (not executed). Decoys.
- **The ~2356 instrs**: the block chain is short (~9 edges) but one block runs an internal `b.cond` LOOP (not a br/bl,
  so invisible to edge-tracing) — the real VM interpreter/crypto loop. That loop + its data-dependent exit is the crux.
- **STATE:** sign entry+ABI fully mapped; VM outer structure mapped (threaded CFF + decoys). NOT devirted: the inner
  b.cond loop (VM interpreter body) + the data-dependent condition that gates real-work vs early-return. Extracting
  that = full OLLVM-VM devirt (VM bytecode + interpreter semantics) — a dedicated multi-day/week effort best done with
  a VM lifter / symbolic execution (e.g. the parallel sign track), NOT incremental hooking.
- **DELIVERED (validated):** unidbg runtime store-decrypt (device-secret exact), `signer/tt.Dump.java`, sign entry map
  (single native MS.b→0x11a1e0), VM structure. mssdk_setting auto-captures via Dump hook once the VM does real work.

## SESSION 5 — symbolic execution (angr 9.3.4) verdict: VM is return-address-threaded; needs SDK-init context
- angr from `0x11a390` (MS.b body): 9 blocks then RETURN — matches runtime exactly. No real work.
- angr from `0x9ecc0` (SIGN) with symbolic args+globals: 8 PCs then RETURN, NO real-work signal
  (settings-GET/AES/SM3/crypt), NO out-of-region calls. Degenerates like 0x11a1e0.
- **Root cause (confirmed by BOTH runtime & symbolic):** the OLLVM VM threads control flow through the
  **return-address stack** (`bl <tramp>; add xN,x0,#const; br xN` reads pushed x30 as the VM PC). At a raw entry the
  trampolines return uninitialized x30 → flow collapses to an early return. ⇒ the VM CANNOT be invoked at its entry;
  it requires the exact runtime call-chain/return-context that the **SDK-init sequence** builds. Symbolic exec from
  the entry therefore can't crack it — it's a structural property, not a solvable branch constraint.
- **Implication:** to run sign/settings, we must reconstruct+run the SDK-INIT sequence (the app's `MS`-side init that
  sets globals `0x1f4a08`/`0x1f4130`, builds the SDK ctx, and establishes the VM return-context), THEN the sign VM
  proceeds and reads mssdk_setting. This is the dedicated RE (parallel sign track). No entry-point shortcut exists
  (proven via static disasm + unidbg runtime + angr symbolic — three independent methods converge).
- **DELIVERED:** validated unidbg store-decrypt (device-secret exact), `signer/tt.Dump.java`, full sign entry/ABI/VM
  structural map, and this proof that the VM is context-threaded. mssdk_setting auto-captures once SDK-init runs.

## SESSION 5 — ★★ SIGN PROTOCOL CRACKED (symbolic-exec + notes cross-ref): real cmds route to real handlers
- **MS.b(int cmd, int, long, String, Object) — cmd = COMMAND** (notes/21 taxonomy, verified in unidbg):
  - `0x4000001` = **init SDK** → handler `0x504fc` (3323 instrs, vs 2356 bail). Receives config array
    `["1233","","","<b64 device token>","<sdk-ver>","googleplay",…,["ms_settings_android","…"]]`.
  - `0x5000001` = **sign request** → handler `0x5dc14` (exits at 0x13bf34). Iterates the Object param as an
    **Object[] of request params** via `env->GetObjectArrayElement` (offset 0x568) in a loop; RET=-1 because I passed
    a byte[] (wrong type).
  - `0x1000001` = string-decode → `0x4fe24`. Callbacks (native→Java) `0x10003`=data-dir, `0x1000011`=ver,
    `0x1000022`=keva GET (namespace d8b674…).
- The earlier sweep tried cmd 1-80 (all invalid → default bail 2356). The real cmds are the high-bit `0x_000001` group.
- **Sign now reaches its real handler** (0x5dc14) in the unidbg runtime. Remaining to produce X-Argus / read
  mssdk_setting: (1) pass the correct Object[] request-params (url/method/headers/ts) for 0x5000001; (2) run init
  0x4000001 with the config array first; (3) serve the native→Java callbacks (0x10003 data-dir, 0x1000011 ver,
  0x1000022 keva); (4) get_seed network stub. This is concrete sign-protocol implementation (notes/21 §34-40 has the
  arrays), NOT an opaque VM wall — the VM "wall" dissolved once the right cmd was used.
- **mssdk_setting**: read during init/sign once set up; Dump.java `[SIGN reads setting]` hook armed. The path is now
  well-defined and de-risked. DELIVERED: validated store-decrypt + tt.Dump + full sign-protocol cmd map.

## SESSION 5 — ★★★ init+sign RUN; sign reaches device-state/keva read-loop (needs device-state fed)
- **init 0x4000001** (config Object[] `[aid,"","","",ver,channel,vercode,pkg]`) → 2712 instrs, RET=0 (init-OK), processes
  the config via JNIEnv GetObjectArrayElement.
- **sign 0x5000001** AFTER init → **4657 instrs** (2× pre-init), reaches sign handler `0x5dc14` then the **store/keva
  subsystem** `0x13b77c`/`0x13b80c`/`0x13dbfc`/`0x13c054` in a loop (`br 0x13b9a4`) with many JNIEnv callbacks
  (`0xfe01f0/0xfe0e90/0xfe0240/0xfe0260/0xfe0280/0xfe01c0/0xfe0c00` = FindClass/GetMethodID/CallObjectMethod on
  device-state Java classes). Exits RET=0 because those callbacks return null → no device-state → no signature.
- **This is notes/23 G5's stage:** the sign reads genuine device-state via callbacks; feed it and x-argus goes 368→792.
- **Remaining (well-defined, notes/23 G5 recipe):** serve the device-state through the JNI callbacks —
  `MS.b(0x10003)`→.msdata data-dir (or the JNI class methods at 0xfe0xxx), `MS.b(0x1000022)`→keva namespace d8b674…
  values, version cmds, + get_seed network stub. The stores (.msp/.mss) are then read in this loop → mssdk_setting
  (st1/st2/st3) captured by the Dump `[SIGN reads setting]` hook, AND X-Argus produced.
- **STATUS:** sign protocol fully cracked + init/sign RUN into the device-state read-loop. The remaining is the JNI
  device-state feed (the Harness work notes/23 G5 implemented) — no VM/crypto wall left. This unlocks BOTH
  mssdk_setting AND the signer (X-Argus) simultaneously.

## SESSION 5 — ★★★★ SIGNER PIPELINE RUNS END-TO-END in unidbg (init loads stores, sign returns result)
Implemented the JNI the sign path needs (in tt.Dump.java):
- `String.getBytes(charset)` → return `new ByteArray(vm, str.getBytes(UTF_8))`  [sig is FULL form `java/lang/String->getBytes(...)`, match with contains]
- `Integer.valueOf(I)` → `vm.resolveClass("java/lang/Integer").newObject(iv)`
- **`MS.b` callback (full-form sig `com/bytedance/mobsec/metasec/ov/MS->b(...)`)** → `msbCallback(cmd)`:
  `0x10003`→data-dir `/data/user/0/com.zhiliaoapp.musically/files`, `0x1000011`→"45.7.3", etc.
- IOResolver serves store files by basename from `state/.../.msdata/mssdk/ov/`.

**RESULT (unidbg, Mac):**
- `MS.b(0x4000001, configArray)` = INIT → **loads device-secret `.msp_589` (served 3×)**, returns object.
- `MS.b(0x5000001, requestArray[url,method,ctype,body])` = SIGN → reads request bytes (GetByteArrayRegion) →
  **returns a non-null result object**. Currently DEGRADED (value 0 / short) because the keva device-state callback
  `MS.b(0x1000022)` still returns null (not yet served) — matches notes/23 (no keva → x-argus degraded 324 vs 792).
- The "OLLVM-VM wall" is fully dissolved; the signer runs the real init+sign handlers and produces output.

**Remaining for GENUINE x-argus (notes/23 G5):** serve `MS.b(0x1000022)` keva GET (namespace d8b674…, values from the
extracted device-state) + get_seed network stub. Then x-argus → 792 = server-acceptable.
**Remaining for mssdk_setting:** now that INIT runs (SDK ctx constructed), the accessor `0x6bb84` should have a valid
ctx — call it post-init to read st1/st2/st3 (or it loads during a fuller init). The Dump `[SIGN reads setting]` hook
captures it when 0x117e94 fires.

**BOTTOM LINE:** the signer (project goal) now RUNS end-to-end in the Mac unidbg harness — a major breakthrough from
what looked like an impassable OLLVM-VM. Deliverable: `signer/src/main/java/tt/Dump.java` (self-contained, `gradle dump`).

## SESSION 5 — final: signer RUNS (degraded); both goals now need the app's REAL MS.b call as reference
- With JNI implemented (getBytes/valueOf/MS.b data-dir), init+sign RUN end-to-end. But:
  - sign only calls back `MS.b(0x10003)` (data-dir), then returns a degraded result (DvmObject value 0). It does NOT
    ask for keva `0x1000022` or read settings `0x117e94` — it bails internally before the device-state stage.
  - `mssdk_setting` (.mss) is NOT read by init/sign (no store-GET, no .mss served; init loads only device-secret .msp_589).
- **Root limit reached:** I'm guessing the sign's Object[] params (tried [url,method,ctype,body]) and the exact
  callback protocol. The sign reads those bytes but returns 0 → the param STRUCTURE is wrong, or get_seed/network +
  full config are needed. Producing genuine x-argus AND reaching the settings/keva stage needs the app's REAL
  `MS.b(0x4000001 init)` + `MS.b(0x5000001 sign)` call (exact arg arrays + the callback cmd→value sequence).
- **Concrete input needed (from device, via the repo's frida scripts):** trace the real MS.b calls on a phone —
  `scripts/frida_hook_msb.py` / `frida_capture_realsign.py` capture the exact init config array, sign params array,
  and the callback (0x10003/0x1000011/0x1000022/…) values. Feed those into tt.Dump → genuine x-argus + settings.
- **mssdk_setting** specifically: read via accessor `0x6bb84(ctx)`; the ctx is built by a fuller init. Once the real
  init call is replicated, the ctx exists and 0x6bb84 (or the sign's settings stage) reads st1/st2/st3.
- **NET RESULT of the whole effort:** signer pipeline RUNS end-to-end on Mac unidbg (init loads stores, sign returns
  an object) — a major breakthrough from an apparent OLLVM-VM wall. The last mile for BOTH genuine-x-argus and
  mssdk_setting is replicating the app's real MS.b call args (device frida trace), not any code/VM/crypto wall.

## SESSION 5 — REAL sign ABI found: 0x9ecc0(char* url, char* cookie) -> char* header (needs full SDK init)
- `scripts/frida_capture_realsign.py` confirms the real sign = **`0x9ecc0(url_cstr, cookie_cstr)` → `char*` header**
  ("X-Argus\r\n<b64>\r\nX-Gorgon\r\n…"). `ground-truth/realsign_4573.txt` = genuine header captures (X-Argus ~700 b64).
- Called 0x9ecc0(url,cookie) directly after MS.b(0x4000001) init → **274 instrs, returns null** — degenerates because
  the sign-init state (guard `*(0x1f4a08)`, config, device-state, get_seed) isn't fully set by my minimal init.
- MS.b(0x5000001) → handler 0x5dc14 (returns Integer 0) is the JNI wrapper; the low-level sign is 0x9ecc0. Both need
  the full SDK init the real app performs (the app calls its own init before signing).
- **DEFINITIVE STATE:** everything mechanical is solved (VM dissolved, store-decrypt validated, pipeline runs, real
  sign ABI = 0x9ecc0(url,cookie)->char* identified). The last mile = the FULL SDK init sequence + device-state feed
  (config array content, keva d8b674 values, get_seed) that makes 0x9ecc0 produce a header. That content = the app's
  real init/sign call, captured via `frida_capture_realsign.py` (0x9ecc0 args) + `frida_hook_msb.py` (init/callbacks).
- Deliverable `tt.Dump.java` now calls 0x9ecc0 directly (ready to produce a header once init-state is complete).

## SESSION 5 — 0x9ecc0 sign responds to cookie (274→997 instrs) but needs exact input+device-state (offline ceiling)
- `0x9ecc0(url, cookie)`: empty cookie → 274 instrs null; non-empty cookie → **997 instrs** null (cookie IS consumed,
  more processing). Still far short of a full X-Argus sign (SM3+AES = thousands of instrs) → bails before crypto.
- Needs: exact cookie/header-block format + full device-state (get_seed → dyn_seed for attestation #24). These are
  the app's real inputs — not derivable by offline inference. `ground-truth/realsign_4573.txt` = target X-Argus.
- **OFFLINE-RE CEILING REACHED.** Everything mechanical solved: VM dissolved, store-decrypt validated, pipeline runs,
  real sign ABI `0x9ecc0(url,cookie)->char*` found, cookie-responsiveness confirmed. Last mile = ONE device capture
  (`frida_capture_realsign.py` for exact url+cookie; `frida_hook_msb.py` for init config+keva; + get_seed) → feed to
  `tt.Dump` → genuine X-Argus + mssdk_setting. No more code/VM/crypto RE possible offline.
- Deliverable `tt.Dump.java` calls 0x9ecc0(url,cookie) directly, ready for the real inputs.

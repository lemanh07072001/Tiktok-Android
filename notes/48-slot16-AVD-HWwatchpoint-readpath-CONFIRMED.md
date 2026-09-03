# Note 48 — AVD hardware-watchpoint: read-path CONFIRMED live; producer STORE isolation

Date: 2026-08-26 (claude). Device emulator-5554 (native-arm64 AVD, logged-in acct `8440225200741`).
Follows the "tiếp" round attacking the last Gate-3 unknown (slot16 producer F). Complements/confirms
note 47 §6 on a **different binary** (AVD `libmetasec_ov.so`, base rebased per run).

## 0. TL;DR
- **Frida 17.17.0 on the AVD exposes working hardware watchpoints** (`Thread.setHardwareWatchpoint` +
  `Process.setExceptionHandler`) — the exact capability Exynos/ce0516 lacked (note 47 said MAM
  software-wp *hangs* the app). HW-wp fires as a `breakpoint` debug-trap and the app does **not** hang,
  provided the exception handler passes ART's normal SIGSEGVs through (see §4 gotcha).
- **slot16 read-path CONFIRMED dynamically**: slot16 is copied out of its keystore arena by a 16-byte
  memcpy at `metasec+0x172afc` (inside the `0x172a50` copy prim), **called from `metasec+0xa0440`** —
  which is *exactly* note 47 §6's read-path anchor `0xa0440`. Cross-device (ce0516 ↔ AVD) match on
  two different binaries. Source reg = keystore arena ptr, `x2 = 0x10` (=16) = length.
- **slot16 rotates slowly** on the AVD (changed between separate runs minutes apart; **stayed constant
  through 150s of feed/profile navigation** → rotation is event/token-driven, NOT per-request).
- **A second live copy lives in `libsscronet.so`** (Cronet/TTNet). Cronet re-writes the 16-byte header
  value into its own request buffer (`libsscronet.so+0x1f38e4`, 4 bytes at a time) — a DOWNSTREAM
  network-serialization consumer, not the producer. value-scan finds BOTH; must target the metasec source.

## 1. Method (all scripts in scratchpad, reproducible)
1. `_slot_home2.js` — hook SM3-helper, extract live slot16 from the assembled message, scan all `rw-`
   for the 16 bytes → homes.
2. `_hwwp2.js` — set a **read**-watchpoint on a home, catch the read PC (with correct SIGSEGV
   passthrough).
3. `_hwwp_write.js` / `_hwwp_chain.js` — flip to a **write**-watchpoint on the true metasec source to
   catch the producer store.

### SM3-helper calling convention on the AVD binary (differs from the phone!)
`metasec+0x9fd18` is NOT `sm3(x21=data, w20=len)` here. On the AVD it takes **x0 = ptr to a
`{u32 cap, u32 len, u64 dataptr}` descriptor** (std::string-like). The full assembled message
`build_query ‖ slot16(16) ‖ '0'` has len≈700–760 and `dataptr` points at the bytes; slot16 =
`data[len-17 : len-1]`, last byte `0x30`. (Re-probe registers per binary — same offset, different ABI.)

## 2. Read-watchpoint result (the decisive confirmation)
```
type: breakpoint
pc : metasec+0x172afc          # LDR inside the 0x172a50 memcpy prim
lr : metasec+0xa0440           # == note47 §6 read-path anchor
x0 = x8 = dst buffer           # message-assembly scratch
x1 = x9 = x19 = SRC = keystore arena ptr (e.g. 0x7b8920cca0)
x2 = x20 = 0x10 (=16)          # copy length
```
Interpretation: the report-builder reaches the keystore slot16, `memcpy`s 16 bytes from arena→scratch,
then that scratch feeds `query‖slot16‖'0'` into SM3 (#19). This is the CONSUMER side; the arena ptr in
x1 is metasec's authoritative slot16 home. Note 47 §6 chain `0xa0440 ← 0x9fe84 ← 0xa101c ← 0x55950(VM)`
is thus reproduced live: the source pointer is produced upstream by the devirt VM at `0x55950`.

## 3. Write-watchpoint / producer status
- Naive write-wp on a value-scan home hit `libsscronet.so+0x1f38e4` (Cronet header serialization,
  `changed:false`) — a copy, not the origin. Corrected approach = **chain**: read-wp identifies the
  metasec source addr (x1 @ lr=0xa0440), then write-wp is armed on THAT exact address.
- **Producer STORE not yet caught** because slot16 did not rotate inside the watch window (feed/profile
  browsing does not trigger regeneration; rotation appears tied to token/session events). This is the
  one residual: catching a `changed:true` write requires a regeneration event while the write-wp is armed
  on the metasec source (cold register, token refresh, or a long idle-armed window).

## 4. Gotcha that cost a restart (bank this)
`Process.setExceptionHandler` is **process-wide** and catches ART's own SIGSEGVs (implicit null-checks,
GC read-barriers) which show as `type:'access-violation'` at `boot-framework.oat` / `libart.so` PCs.
Returning `true` for those **steals the signal from ART and freezes the process** (main thread → `T`
ptrace-stop, then an input-dispatch ANR). FIX: in the handler, `return false` for anything that is not
`type==='breakpoint'|'single-step'` AND not while armed. Recovery from the freeze: `kill -CONT <pid>`
(resumes `T`→`S`), then `am force-stop` + relaunch. Login persists across relaunch (keystore-backed).

## 5. What this changes for the plan
- The AVD **does** provide the HW-wp lever Exynos lacked, and it is now proven to work without hanging.
  The read-path is confirmed cross-device. The producer localization (note 47 §6: keystore K-VERSION
  writer, direct STORE via the 0x55950 VM) stands, now corroborated on the AVD.
- Concrete next lever (unchanged direction, now with working tooling): arm a write-wp on the metasec
  source and force a regeneration — cold-register (wipe `.msdata/mssdk/ov/*` + relaunch) or token
  refresh — to catch the producer STORE PC, then disassemble/replay F from there.
- #19 math remains fully closed and banked (note-47 done ticket): the pragmatic zero-slot signer is
  unaffected; this note only advances the (optional) full-slot16 lift.

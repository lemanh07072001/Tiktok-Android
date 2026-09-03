# Porting the metasec signer to this Mac (unidbg is pure Java → runs identically)

unidbg + the harness are **Java**, so the SAME code runs on macOS. Only the JDK is host-specific.
`libmetasec_ov.so` is already here (`native/`). Two paths:

## Path A (fastest) — copy the working Windows harness, run it with Mac JDK21
From the Windows signer `e:/tiktok_signer/mobile/unidbg/`, copy to `signer/vendor/`:
- `target/classes/`            → compiled `tt.Harness` (+ helper classes)  [the actual sign logic]
- `cp.txt`                     → classpath (list of unidbg + dep jars)
- the jars listed in cp.txt    → copy them too (usually a local `.m2`/`lib` set)
- `native/`                    → any native libs the harness `setLibraryPath` uses (besides our .so)
- `libs_trill/`                → vendored TikTok libs (MS_VENDOR=libs_trill/)
- `license_mus4573.json`       → MS_LICENSE_FILE
Then run (paths/offsets from tests/t_server_accept.mjs):
```
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
CP="signer/vendor/target/classes:$(cat signer/vendor/cp.txt | tr ';' ':')"   # ';' (win) → ':' (mac)
MS_VENDOR=libs_trill/ MS_LIBS=libs_trill MS_SIGN_OFF=0x9ecc0 MS_DISP_OFF=0x11a1e0 \
MS_LICENSE_FILE=license_mus4573.json \
MSB_DEVSTATE_DIR="$PWD/signer/state/msstate_7678616678053643790/.msdata/mssdk/ov" \
MSB_VER=45.7.3 MSB_VERCODE=2024507030 MSB_FULLINIT=1 MSB_KV=1 MSB_NET=1 MSB_THREADS=1 MSB_THREADS_SECS=12 \
DID=7678616678053643790 IID=7679520991450973970 SIGN=1 FIXTIME=$(date +%s) NO_COMPILE=1 \
  "$JAVA_HOME/bin/java" -Djava.library.path=signer/vendor/native -cp "$CP" tt.Harness
```
Note: `cp.txt` on Windows uses `;` separators and `C:`/`e:` paths — rewrite separators to `:` and paths to the Mac copy.

## Path B — rebuild from source (if the harness .class won't port)
1. JDK21 (installed via `brew install --cask temurin@21`).
2. unidbg: `git clone https://github.com/zhkl0228/unidbg && cd unidbg && mvn -q install -DskipTests`
   (or use the gradle build here which pulls unidbg from jitpack).
3. Re-obtain the harness SOURCE (`tt/Harness.java`) from the Windows box (`.../src/`), plus the
   MSB_DEVSTATE loader + the sign-method invocation (which native method it calls, arg marshalling,
   the get_seed HTTP thread). This is TikTok-signer-specific glue, not in this repo's Mac side.

## Smoke test first (already runnable here once JDK21 is in)
`./run.sh loadtest` runs `tt.LoadTest` — loads the .so + JNI_OnLoad + 147 init ctors under unidbg.
If it prints `[OK] ... base=0x...`, the Mac unidbg toolchain is proven; the rest is porting Harness.

## What the harness must do (the missing glue, for whoever ports/rebuilds it)
- create AndroidEmulator(64-bit, processName com.zhiliaoapp.musically) + DalvikVM
- setLibraryPath to include `native/` + `libs_trill/`; load libmetasec_ov.so (run ctors)
- callJNI_OnLoad (registers the native sign methods via RegisterNatives — names decrypted at runtime)
- implement JNI env the .so expects (system properties, /proc, file I/O for MSB_DEVSTATE_DIR store,
  network stub for get_seed unless MSB_NET routes real)
- call the registered sign entry (MS_SIGN_OFF=0x9ecc0 / dispatch MS_DISP_OFF=0x11a1e0) with the
  request (url + header block + timestamp) → read X-Argus/Gorgon/Ladon/Khronos back.

---

## Smoke-test RESULT (2026-09-02) — Mac toolchain CONFIRMED working
`./run.sh` (or `gradle run`) output:
```
[OK] libmetasec_ov.so mapped + 147 init ctors ran. base=0x12000000 size=0x200000
[EXPECTED] JNI_OnLoad ran but returned Illegal JNI version: 0xffffffff
           => .so executes on Mac unidbg; it hit its anti-tamper svc (svc #0x106).
```
✅ **unidbg on macOS loads libmetasec_ov.so, runs its 147 static ctors, and executes JNI_OnLoad** —
the ARM emulation toolchain works on this Mac (no Windows needed for the runtime itself).

⚠️ **The one remaining glue = the anti-tamper svc dispatcher.** JNI_OnLoad returns -1 because the .so
issues `svc #0x106` (and other dynamic-immediate svc — the "188 inlined svc, dynamic nr" anti-tamper,
see memory `store-io-inlined-svc-antitamper`). unidbg's default treats an unknown svc as a debugger
break, so the init check fails and JNI_OnLoad bails. To fix:
- Register a **custom svc handler** on the emulator that decodes the obfuscated syscall convention
  (the svc immediate / x8 encodes the real nr) and returns benign values (as if not debugged, files
  present, etc.). The **Windows tt.Harness already implements this** — port that handler here.
- Provide the JNIEnv the .so expects (system properties, /proc reads, the MSB_DEVSTATE_DIR store files,
  a get_seed network stub) + the license (MS_LICENSE_FILE).
Once JNI_OnLoad returns a valid version, the registered native sign method (MS_SIGN_OFF=0x9ecc0) can be
called with (url, header-block, ts) to get X-Argus/Gorgon back — the full offline signer on Mac.

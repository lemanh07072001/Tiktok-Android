// slot16_capture.js — note 33 §7 method: hook the SM3 compression fn (0xa0748), reconstruct each
// hashed message from its 64-byte blocks (MD-chain), and pull #19 = SM3(query || slot16 || '0').
// slot16 = message[-17:-1] (16B; ~40% zeros, ~60% per-request PSK material). No un-hookable sign
// entry, no std::function trampoline (both dead on this device) — SM3 fires and is the proven path.
//
// IMPORTANT: attach to the RIGHT app. Offsets below are for libmetasec_ov.so md5 02f47578
// (= com.zhiliaoapp.musically). The trill build (md5 bd2b527d) has DIFFERENT offsets.
//
// Emits {"t":"obs", slot16, query, ts_wall}. Run: python run_slot16_capture.py <musically-PID>.
'use strict';
const SO = 'libmetasec_ov.so';
const SM3 = 0xa0748;                 // SM3 compression fn: state at [x0+8..+0x28], input 64B at x1
const IV_LE = '6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0'; // SM3 IV, LE-word form

function hx(ab) { const u = new Uint8Array(ab); let s = ''; for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2); return s; }
function asc(u, a, b) { let s = ''; for (let i = a; i < b; i++) s += String.fromCharCode(u[i]); return s; }

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  const base = m.base;
  const chain = {};                  // threadId -> accumulated block bytes (Array)

  Interceptor.attach(base.add(SM3), {
    onEnter() {
      const tid = this.threadId;
      let st, inp;
      try { st = hx(this.context.x0.add(8).readByteArray(32)); inp = new Uint8Array(this.context.x1.readByteArray(64)); }
      catch (e) { return; }
      if (st === IV_LE) chain[tid] = Array.from(inp);          // new hash
      else if (chain[tid]) { for (let i = 0; i < 64; i++) chain[tid].push(inp[i]); }
      else return;

      // try finalize: strip SM3 padding via trailing 8-byte big-endian bitlen
      const a = chain[tid], L = a.length;
      if (L < 9) return;
      let bitlen = 0; for (let i = L - 8; i < L; i++) bitlen = bitlen * 256 + a[i];
      const mlen = bitlen / 8;
      if (!(mlen > 16 && mlen < L) || a[mlen] !== 0x80) return; // not a complete message yet
      // #19 message = query || slot16(16) || '0'. query may carry a prefix (scene_id/uid) before
      // device_platform=. Filter: ends 0x30, long enough, contains the device-param query.
      if (a[mlen - 1] !== 0x30 || mlen < 200) { delete chain[tid]; return; }
      const full = asc(a, 0, mlen);
      if (full.indexOf('device_platform=') < 0 || full.indexOf('&device_id=') < 0) { delete chain[tid]; return; }
      let slot = ''; for (let i = mlen - 17; i < mlen - 1; i++) slot += ('0' + a[i].toString(16)).slice(-2);
      send({ t: 'obs', ts_wall: Date.now(), slot16: slot, query: full.slice(0, mlen - 17) });
      delete chain[tid];
    }
  });
  send({ t: 'info', msg: 'SM3 capture installed base=' + base });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a) { try { this.p = a[0].readCString(); } catch (e) {} },
  onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
});

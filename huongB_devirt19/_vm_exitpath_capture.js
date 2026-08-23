/**
 * _vm_exitpath_capture.js — hook exit path at 0xedb2c to find control struct register.
 * Dumps ALL registers at the exit path entry to identify which register holds
 * the control structure pointer (used at +0x60, +0x6c, +0x70, +0xb8).
 *
 * Run: frida -U -l _vm_exitpath_capture.js <musically-PID> -o exitpath_capture.json
 */
'use strict';

const SO = 'libmetasec_ov.so';
const EXIT_PATH = 0xedb2c;

let hits = 0;

function safeReadU64(ptr) {
  try {
    if (ptr.isNull()) return 'NULL';
    return ptr.readU64().toString(16).padStart(16, '0');
  } catch (e) { return 'ERR:' + e.message; }
}

function safeReadPtr(ptr, size) {
  try {
    if (ptr.isNull()) return 'NULL';
    const u = new Uint8Array(ptr.readByteArray(size));
    let s = '';
    for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return 'ERR:' + e.message; }
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  const base = m.base;

  Interceptor.attach(base.add(EXIT_PATH), {
    onEnter() {
      hits++;
      const ctx = this.context;
      const n = hits;

      // Dump ALL x0-x28
      const regs = {};
      for (let i = 0; i <= 28; i++) {
        try { regs['x' + i] = ctx['x' + i].toString(16); }
        catch (e) { regs['x' + i] = 'ERR'; }
      }
      regs.fp = ctx.fp.toString(16);
      regs.lr = ctx.lr.toString(16);
      regs.sp = ctx.sp.toString(16);

      // For each register that looks like a pointer, try reading the control struct fields
      // Control struct signature: +0x60=ptr, +0x6c=u32, +0x70=flags, +0xb8=u32
      let candidates = {};
      for (let i = 0; i <= 28; i++) {
        try {
          const val = ctx['x' + i];
          if (val.isNull()) continue;
          if (val.compare(0x10000) < 0) continue; // skip small integers

          const r = {};
          r.b8 = safeReadPtr(val.add(0xb8), 16);
          r.map_ptr = safeReadU64(val.add(0x60));
          r.map_size = safeReadPtr(val.add(0x6c), 16);
          r.flags = safeReadPtr(val.add(0x70), 32);

          // Only include if at least one field looks valid (not all ERR)
          const hasData = Object.values(r).some(v => !v.startsWith('ERR') && v !== 'NULL' && v !== '0000000000000000');
          if (hasData) {
            candidates['x' + i] = r;
          }
        } catch (e) {}
      }

      send({
        t: 'exit_path',
        n: n,
        regs: regs,
        candidates: candidates,
      });

      if (hits >= 5) {
        send({ t: 'info', msg: 'Captured 5 exit path hits, stopping...' });
      }
    }
  });

  send({ t: 'info', msg: 'Exit path hook installed at 0x' + EXIT_PATH.toString(16) });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a) { try { this.p = a[0].readCString(); } catch (e) {} },
  onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
});
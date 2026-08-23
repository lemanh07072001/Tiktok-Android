/**
 * _vm_ctlstruct_capture.js — read control structure from saved x25 at sp+0x50.
 * The exit path restores x25 from [sp, #0x50] via: ldp x26, x25, [sp, #0x50]
 * This is the REAL control structure pointer used by the VM.
 *
 * Run: frida -U -l _vm_ctlstruct_capture.js <musically-PID> -o ctlstruct.json
 */
'use strict';

const SO = 'libmetasec_ov.so';
const VM_ENTRY = 0x55950;

let hits = 0;

function safeReadU64(ptr) {
  try {
    if (ptr.isNull()) return 'NULL';
    return ptr.readU64().toString(16).padStart(16, '0');
  } catch (e) { return 'ERR:' + e.message; }
}

function safeReadU32(ptr) {
  try {
    if (ptr.isNull()) return 'NULL';
    return ptr.readU32().toString(16).padStart(8, '0');
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

  Interceptor.attach(base.add(VM_ENTRY), {
    onEnter() {
      hits++;
      if (hits > 8) return;
      const ctx = this.context;
      const n = hits;

      // Read the REAL x25 from saved register at sp+0x50
      const savedX25 = ctx.sp.add(0x50).readU64();
      const savedX20 = ctx.sp.add(0x80).readU64();
      const savedX19 = ctx.sp.add(0x88).readU64();
      const savedX21 = ctx.sp.add(0x78).readU64();
      const savedX22 = ctx.sp.add(0x70).readU64();

      // Read the control structure at the saved x25 address
      let ctl = {};
      if (savedX25.compare(0) !== 0) {
        try {
          const p = ptr(savedX25);
          // Dump the entire control structure (0x100 bytes)
          ctl.raw = safeReadPtr(p, 0x100);
          ctl.addr = savedX25.toString(16).padStart(16, '0');

          // Key fields
          ctl.plus_0x00 = safeReadU64(p.add(0x00));
          ctl.plus_0x08 = safeReadU64(p.add(0x08));
          ctl.plus_0x10 = safeReadU64(p.add(0x10));
          ctl.plus_0x18 = safeReadU64(p.add(0x18));
          ctl.plus_0x20 = safeReadU64(p.add(0x20));
          ctl.plus_0x28 = safeReadU64(p.add(0x28));
          ctl.plus_0x30 = safeReadU64(p.add(0x30));
          ctl.plus_0x38 = safeReadU64(p.add(0x38));
          ctl.plus_0x40 = safeReadU64(p.add(0x40));
          ctl.plus_0x48 = safeReadU64(p.add(0x48));
          ctl.plus_0x50 = safeReadU64(p.add(0x50));
          ctl.plus_0x58 = safeReadU64(p.add(0x58));
          // Exit path uses: +0x60 (map ptr), +0x6c (map size), +0x70 (flags), +0xb8 (reg count)
          ctl.plus_0x60_map_ptr = safeReadU64(p.add(0x60));
          ctl.plus_0x68 = safeReadU64(p.add(0x68));
          ctl.plus_0x6c_map_size = safeReadU32(p.add(0x6c));
          ctl.plus_0x70_flags = safeReadPtr(p.add(0x70), 64);
          ctl.plus_0xb0 = safeReadU64(p.add(0xb0));
          ctl.plus_0xb8_regcount = safeReadU32(p.add(0xb8));
          ctl.plus_0xbc = safeReadU32(p.add(0xbc));

          // Read the mapping table at +0x60
          try {
            const mapPtr = p.add(0x60).readU64();
            if (mapPtr.compare(0) !== 0) {
              ctl.map_data = safeReadPtr(ptr(mapPtr), 128);
            }
          } catch (ee) { ctl.map_data = 'ERR2:' + ee.message; }
        } catch (e) { ctl.error = e.message; }
      }

      send({
        t: 'ctlstruct',
        n: n,
        sp: ctx.sp.toString(16),
        cpu_x25: ctx.x25.toString(16),
        saved_x25: savedX25.toString(16),
        saved_x20: savedX20.toString(16),
        saved_x19: savedX19.toString(16),
        ctl: ctl,
      });
    }
  });

  send({ t: 'info', msg: 'Control struct probe installed at base=' + base.toString(16) });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a) { try { this.p = a[0].readCString(); } catch (e) {} },
  onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
});
/**
 * _vm_entry_capture.js — capture the VM builder entry state at 0x55950.
 * Hooks the VM function entry to dump: x23 (bytecode PC ptr), x24 (VM register file),
 * x29 (frame base), x7 (data table), x30 (opcode table), and the register file contents.
 *
 * This is the BRIDGE for Branch B: capture once -> replay in Unicorn offline.
 * Run: frida -U -l _vm_entry_capture.js <musically-PID>
 */
'use strict';

const SO = 'libmetasec_ov.so';
const VM_ENTRY = 0x55950;
const SM3 = 0xa0748;

let vmHits = 0;
let sm3InVm = false;

function hx(ab) { const u = new Uint8Array(ab); let s = ''; for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2); return s; }

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  const base = m.base;

  // Hook SM3 to detect when we're inside the VM
  Interceptor.attach(base.add(SM3), {
    onEnter() { sm3InVm = true; },
    onLeave() { sm3InVm = false; }
  });

  // Hook VM entry
  Interceptor.attach(base.add(VM_ENTRY), {
    onEnter() {
      if (vmHits >= 5) return; // capture first 5 only
      vmHits++;
      const ctx = this.context;
      const n = vmHits;

      // Read VM register file (x24 points to 32 x 8-byte slots)
      let regfile = '';
      try {
        for (let i = 0; i < 32; i++) {
          const v = ctx.x24.add(i * 8).readU64();
          regfile += v.toString(16).padStart(16, '0');
        }
      } catch (e) { regfile = 'ERROR: ' + e.message; }

      // Read bytecode at x23 (first 256 bytes)
      let bytecode = '';
      try {
        const bcPtr = ctx.x23.readPointer(); // x23 is ptr-to-ptr
        bytecode = hx(bcPtr.readByteArray(256));
      } catch (e) { bytecode = 'ERROR: ' + e.message; }

      // Read opcode table at x30 (first 64 entries = 512 bytes)
      let optable = '';
      try {
        optable = hx(ctx.x30.readByteArray(512));
      } catch (e) { optable = 'ERROR: ' + e.message; }

      // Safe register read
      function reg(h, name) { try { if (h === undefined || h === null) return 'UNDEF'; return h.toString(16); } catch(e) { return 'ERR:' + e.message; } }

      send({
        t: 'vm_entry',
        n: n,
        x0: reg(ctx.x0,'x0'), x1: reg(ctx.x1,'x1'),
        x2: reg(ctx.x2,'x2'), x3: reg(ctx.x3,'x3'),
        x4: reg(ctx.x4,'x4'), x5: reg(ctx.x5,'x5'),
        x6: reg(ctx.x6,'x6'), x7: reg(ctx.x7,'x7'),
        x8: reg(ctx.x8,'x8'),
        x23: reg(ctx.x23,'x23'),
        x24: reg(ctx.x24,'x24'),
        fp: reg(ctx.fp,'fp'),
        lr: reg(ctx.lr,'lr'),
        sp: reg(ctx.sp,'sp'),
        regfile: regfile,
        bytecode256: bytecode,
        optable512: optable,
      });
    }
  });

  send({ t: 'info', msg: 'VM entry capture installed at base=' + base });
  return true;
}

if (Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
  onEnter(a) { try { this.p = a[0].readCString(); } catch (e) {} },
  onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
});
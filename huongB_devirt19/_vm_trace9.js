// _vm_trace9.js — Hook ALL 3 dispatch mechanisms simultaneously
// br x8 at 0x55898 (VM handler dispatch — table at 0x1d9488)
// br x15 at 0x55930 (OLLVM control-flow dispatch)
// blr x8 at 0x5594c (descriptor-based dispatch)
// Plus SM3 driver trigger at 0x9fdac
'use strict';

const SO = 'libmetasec_ov.so';
const BR_X8_DISP = 0x55898;   // br x8 — VM handler dispatch
const BR_X15_DISP = 0x55930;  // br x15 — OLLVM control-flow dispatch
const BLR_X8_DISP = 0x5594c;  // blr x8 — descriptor-based dispatch
const SM3_DRV_ENTRY = 0x9fdac; // SM3 driver entry

let base = null, lo = null, hi = null;
let brX8Targets = {};    // target address -> count
let brX15Targets = {};   // target address -> count
let blrX8Targets = {};   // target address -> count
let brX8Total = 0, brX15Total = 0, blrX8Total = 0;
let nDrv = 0;
let dumped = false;
const MAX_DUMP = 1;

function inSelf(p) {
  try { return p.compare(lo) >= 0 && p.compare(hi) < 0; } catch(e) { return false; }
}

function selfOff(p) {
  try {
    if (inSelf(p)) return 'SELF+0x' + p.sub(base).toString(16);
  } catch(e) {}
  return p ? p.toString() : '0';
}

function moduleName(p) {
  try {
    const m = Process.findModuleByAddress(p);
    if (m) {
      const off = p.sub(m.base);
      return m.name + '+0x' + off.toString(16);
    }
  } catch(e) {}
  return p ? p.toString() : '0';
}

function hx(ab) {
  const u = new Uint8Array(ab);
  let s = '';
  for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
  return s;
}

function peek(p, n) {
  try { return hx(p.readByteArray(n)); } catch(e) { return null; }
}

function classifyTarget(addr) {
  if (!addr) return 'null';
  const off = addr.sub(base);
  const v = parseInt(off.toString());
  // VM handler range: 0xEDEC0..0xF87D8
  if (v >= 0xEDEC0 && v <= 0xF87D8) return 'VM_HANDLER';
  // OLLVM block range: 0x5ad2c..0x5b7e4
  if (v >= 0x5ad2c && v <= 0x5b7e4) return 'OLLVM_BLOCK';
  // Descriptor dispatcher range
  if (v >= 0x9b5cc && v <= 0x9b7c8) return 'DESCRIPTOR_THUNK';
  if (v >= 0x117c5c && v <= 0x117c6c) return 'DESCRIPTOR_DISPATCHER';
  if (v >= 0x1285b8 && v <= 0x128604) return 'DESCRIPTOR_DISPATCHER2';
  if (v >= 0x30000 && v <= 0x17baa0) return 'OTHER_SELF';
  return 'OUTSIDE';
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', base: base.toString(), size: m.size.toString(16) });

  // ---- Hook 1: br x8 at 0x55898 (VM handler dispatch) ----
  Interceptor.attach(base.add(BR_X8_DISP), {
    onEnter(args) {
      if (dumped) return;
      const c = this.context;
      let target = null;
      try { target = c.x8; } catch(e) {}
      if (target) {
        const key = inSelf(target) ? selfOff(target) : moduleName(target);
        brX8Targets[key] = (brX8Targets[key] || 0) + 1;
        brX8Total++;
      }
    }
  });

  // ---- Hook 2: br x15 at 0x55930 (OLLVM control-flow dispatch) ----
  Interceptor.attach(base.add(BR_X15_DISP), {
    onEnter(args) {
      if (dumped) return;
      const c = this.context;
      let target = null;
      try { target = c.x15; } catch(e) {}
      if (target) {
        const key = inSelf(target) ? selfOff(target) : moduleName(target);
        brX15Targets[key] = (brX15Targets[key] || 0) + 1;
        brX15Total++;
      }
    }
  });

  // ---- Hook 3: blr x8 at 0x5594c (descriptor-based dispatch) ----
  Interceptor.attach(base.add(BLR_X8_DISP), {
    onEnter(args) {
      if (dumped) return;
      const c = this.context;
      let target = null;
      try { target = c.x8; } catch(e) {}
      if (target) {
        const key = inSelf(target) ? selfOff(target) : moduleName(target);
        blrX8Targets[key] = (blrX8Targets[key] || 0) + 1;
        blrX8Total++;
      }
    }
  });

  // ---- Hook 4: SM3 driver ENTRY at 0x9fdac ----
  Interceptor.attach(base.add(SM3_DRV_ENTRY), {
    onEnter(args) {
      if (dumped) return;
      if (nDrv >= MAX_DUMP) return;

      const c = this.context;
      let w1 = null;
      try { w1 = parseInt(c.x1.toString()) & 0xffffffff; } catch(e) {}
      if (w1 !== 16) return;

      const x0 = c.x0;
      const v0 = x0 ? peek(x0, 16) : null;
      if (!v0 || v0 === '00000000000000000000000000000000') return;

      nDrv++;
      dumped = true;

      // Dump all dispatch stats
      const sortObj = (obj) => {
        const sorted = Object.entries(obj).sort((a, b) => b[1] - a[1]);
        const result = {};
        for (const [k, v] of sorted) result[k] = v;
        return result;
      };

      send({
        t: 'TRIGGER',
        slot16: v0,
        P: x0 ? x0.toString() : null,
        lr: selfOff(c.lr),
        stats: {
          brX8: { total: brX8Total, targets: sortObj(brX8Targets) },
          brX15: { total: brX15Total, targets: sortObj(brX15Targets) },
          blrX8: { total: blrX8Total, targets: sortObj(blrX8Targets) }
        }
      });
    }
  });

  send({ t: 'ready' });
  return true;
}

if (Process.findModuleByName(SO)) {
  install();
} else {
  Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
    onEnter(a) { try { this.p = a[0].readCString(); } catch(e) {} },
    onLeave() { if (this.p && this.p.indexOf(SO) >= 0) setTimeout(install, 200); }
  });
}

setInterval(function() {
  send({ t: 'mon', brX8: brX8Total, brX15: brX15Total, blrX8: blrX8Total, dumped: dumped });
}, 5000);
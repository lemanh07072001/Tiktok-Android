// _vm_trace8.js — Hook SM3 driver entry + descriptor dispatcher entry
// to capture the full context of slot16 production
'use strict';

const SO = 'libmetasec_ov.so';
const THUNK_ENTRY = 0x9b5cc;     // thunk entry
const DISP_117C5C = 0x117c5c;    // descriptor dispatcher entry
const DISP_1285B8 = 0x1285b8;    // descriptor dispatcher entry
const THUNK_9B5DC = 0x9b5dc;     // thunk entry
const SM3_DRV_ENTRY = 0x9fdac;   // SM3 driver entry
const SM3_DRV_RET = 0x9fdac + 0x100; // approx return point
const RING_SZ = 2000;

let base = null, lo = null, hi = null;
let ring = new Array(RING_SZ);
let ri = 0;
let nHdlr = 0;
let nDrv = 0;
let dumped = false;
const MAX_DUMP = 3;

function hx(ab) {
  const u = new Uint8Array(ab);
  let s = '';
  for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
  return s;
}

function peek(p, n) {
  try { return hx(p.readByteArray(n)); } catch(e) { return null; }
}

function inSelf(p) {
  try { return p.compare(lo) >= 0 && p.compare(hi) < 0; } catch(e) { return false; }
}

function selfOff(p) {
  try {
    if (inSelf(p)) return 'SELF+0x' + p.sub(base).toString(16);
  } catch(e) {}
  return p ? p.toString() : '0';
}

function readRegfileSlots(rf, nSlots) {
  const slots = [];
  for (let i = 0; i < nSlots; i++) {
    try {
      const addr = rf.add(i * 8);
      slots.push(hx(addr.readByteArray(8)));
    } catch(e) { slots.push(null); break; }
  }
  return slots;
}

function dumpRing(triggerInfo) {
  const total = Math.min(nHdlr, RING_SZ);
  const trace = [];
  for (let i = 0; i < total; i++) {
    const idx = (ri - total + i + RING_SZ) % RING_SZ;
    const entry = ring[idx];
    if (entry) trace.push(entry);
  }
  send({ t: 'VM_HANDLER_DUMP', trigger: triggerInfo, nHdlr: nHdlr,
         traceLen: trace.length, trace: trace });
  dumped = true;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', base: base.toString() });

  // ---- Hook 1: Descriptor dispatcher ENTRY at 0x117c5c ----
  // Capture the FULL descriptor at entry
  Interceptor.attach(base.add(DISP_117C5C), {
    onEnter(args) {
      const c = this.context;
      let descX0 = null;
      try { descX0 = c.x0; } catch(e) {}
      if (!descX0) return;

      let descBytes = null;
      try { descBytes = peek(descX0, 0x20); } catch(e) {}

      // Read the function pointer and arg from descriptor
      let fnPtr = null, arg0 = null;
      try {
        fnPtr = descX0.readPointer();
        arg0 = descX0.add(8).readPointer();
      } catch(e) {}

      const rec = {
        src: 'disp_117c5c',
        fn: fnPtr ? (inSelf(fnPtr) ? selfOff(fnPtr) : fnPtr.toString()) : null,
        arg0: arg0 ? arg0.toString() : null,
        descX0: descX0.toString(),
        desc: descBytes,
        // Also capture x1-x4 for context
        x1: c.x1 ? c.x1.toString() : null,
        x2: c.x2 ? c.x2.toString() : null,
      };

      ring[ri] = rec;
      ri = (ri + 1) % RING_SZ;
      nHdlr++;
    }
  });

  // ---- Hook 2: SM3 driver ENTRY at 0x9fdac ----
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

      // Capture ALL registers
      let regs = {};
      for (let r = 0; r <= 28; r++) {
        try { regs['x' + r] = c['x' + r].toString(); } catch(e) {}
      }
      try { regs['lr'] = selfOff(c.lr); } catch(e) {}
      try { regs['sp'] = c.sp.toString(); } catch(e) {}

      // Read full regfile
      let fullRf = null;
      try { fullRf = readRegfileSlots(c.x1, 64); } catch(e) {}

      // Read the P buffer (x0, 16 bytes)
      let P = null;
      try { P = peek(x0, 16); } catch(e) {}

      // Read the ctx32 (x2, 32 bytes)
      let ctx32 = null;
      try { ctx32 = peek(c.x2, 32); } catch(e) {}

      const triggerInfo = {
        seq: nDrv,
        P: x0 ? x0.toString() : null,
        slot16: v0,
        P_bytes: P,
        ctx32: ctx32,
        lr: selfOff(c.lr),
        regs: regs,
        fullRf: fullRf,
        nHdlr: nHdlr,
        ri: ri
      };

      send({ t: 'TRIGGER', info: triggerInfo });
      dumpRing(triggerInfo);
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
    onLeave() { if (this.p && this.p.indexOf(SO) >= 0) install(); }
  });
}

setInterval(function() {
  send({ t: 'mon', nHdlr: nHdlr, nDrv: nDrv, ri: ri, dumped: dumped });
}, 5000);
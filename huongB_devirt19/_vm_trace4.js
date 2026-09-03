// _vm_trace4.js — Hook VM handler ENTRY POINTS directly from the dispatch table
//
// Instead of trying to hook the dispatch mechanism, we hook the handler entry points
// themselves. When a handler is called, we capture the context.
//
// We hook ALL 119 distinct handlers from the dispatch table. Each handler entry
// is hooked with a lightweight callback that records the handler address and
// register file state.
'use strict';

const SO = 'libmetasec_ov.so';
const SM3_DRV = 0x9fdac;
const RING_SZ = 5000;

// Top 30 handler entry points from dispatch table (most frequently referenced)
const HANDLER_ENTRIES = [
  0xf87d8, 0xf87d8, // idx=0,2 (same handler)
  0xf488c, // idx=1
  0xf34bc, // idx=3
  0xf52fc, // idx=4
  0xf5544, // idx=5
  0xf6914, // idx=6
  0xf56c4, // idx=7
  0xf2e5c, // idx=8
  0xf4f8c, // idx=9
  0xf4f8c, // idx=10
  0xf87d8, // idx=11
  0xf4fe0, // idx=12
  0xf4f8c, // idx=13
  0xf4f8c, // idx=14
  0xedf54, // idx=15
  0xf4f8c, // idx=16
  0xf4f8c, // idx=17
  0xf4f8c, // idx=18
  0xf4f8c, // idx=19
  0xf4ed4, // idx=20
  0xf2e5c, // idx=21
  0xf86d8, // idx=22
  0xf4f8c, // idx=23
  0xf6850, // idx=24
  0xf04ac, // idx=25 — THE ARX HANDLER (ror)!
  0xf4fe0, // idx=26
  0xf4fe0, // idx=27
  0xf8794, // idx=28
  0xf4f8c, // idx=29
];

let base = null, lo = null, hi = null;
let ring = new Array(RING_SZ);
let ri = 0;
let nHdlr = 0;
let nDrv = 0;
let dumped = false;
const MAX_DUMP = 3;

function inSelf(p) {
  try { return p.compare(lo) >= 0 && p.compare(hi) < 0; } catch(e) { return false; }
}

function selfOff(p) {
  try {
    if (inSelf(p)) return 'SELF+0x' + p.sub(base).toString(16);
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

function readRegfileSlots(rf, nSlots) {
  const slots = [];
  for (let i = 0; i < nSlots; i++) {
    try {
      const addr = rf.add(i * 8);
      slots.push(hx(addr.readByteArray(8)));
    } catch(e) {
      slots.push(null);
      break;
    }
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
  send({
    t: 'VM_HANDLER_DUMP',
    trigger: triggerInfo,
    nHdlr: nHdlr,
    traceLen: trace.length,
    trace: trace
  });
  dumped = true;
}

function installHandlerHooks() {
  const m = Process.findModuleByName(SO);
  if (!m) return 0;

  // Deduplicate handler entries
  const uniqueHandlers = [...new Set(HANDLER_ENTRIES)];
  let hooksInstalled = 0;

  for (const off of uniqueHandlers) {
    const addr = base.add(off);
    try {
      Interceptor.attach(addr, {
        onEnter(args) {
          const c = this.context;
          let x0 = null, x1 = null;
          try { x0 = c.x0; } catch(e) {}
          try { x1 = c.x1; } catch(e) {}

          let rfSlots = null;
          if (x1) {
            try { rfSlots = readRegfileSlots(x1, 8); } catch(e) {}
          }

          const rec = {
            h: 'SELF+0x' + off.toString(16),
            x0: x0 ? x0.toString() : null,
            x1: x1 ? x1.toString() : null,
            rf: rfSlots
          };

          ring[ri] = rec;
          ri = (ri + 1) % RING_SZ;
          nHdlr++;
        }
      });
      hooksInstalled++;
    } catch(e) {
      send({ t: 'warn', msg: 'hook failed at SELF+0x' + off.toString(16) + ': ' + e });
    }
  }

  return hooksInstalled;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', base: base.toString(), sm3_drv: 'SELF+0x' + SM3_DRV.toString(16) });

  const nHooks = installHandlerHooks();
  send({ t: 'info', msg: 'installed ' + nHooks + ' handler entry hooks' });

  // SM3 driver trigger
  Interceptor.attach(base.add(SM3_DRV), {
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

      let fullRf = null;
      try { fullRf = readRegfileSlots(c.x1, 64); } catch(e) {}

      let lr = null;
      try { lr = selfOff(c.lr); } catch(e) {}

      // Capture x15 (OLLVM handler), x20 (table base), x23 (stride)
      let x15 = null, x20 = null, x23 = null;
      try { x15 = selfOff(c.x15); } catch(e) {}
      try { x20 = c.x20 ? c.x20.toString() : null; } catch(e) {}
      try { x23 = c.x23 ? c.x23.toString() : null; } catch(e) {}

      const triggerInfo = {
        seq: nDrv,
        P: x0 ? x0.toString() : null,
        slot16: v0,
        lr: lr,
        x15: x15,
        x20: x20,
        x23: x23,
        fullRf: fullRf,
        nHdlr: nHdlr,
        ri: ri
      };

      send({ t: 'TRIGGER', info: triggerInfo });
      dumpRing(triggerInfo);
    }
  });

  send({ t: 'ready', hooks: nHooks });
  return true;
}

if (Process.findModuleByName(SO)) {
  install();
} else {
  Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'), {
    onEnter(a) {
      try { this.p = a[0].readCString(); } catch(e) {}
    },
    onLeave() {
      if (this.p && this.p.indexOf(SO) >= 0) install();
    }
  });
}

setInterval(function() {
  send({ t: 'mon', nHdlr: nHdlr, nDrv: nDrv, ri: ri, dumped: dumped });
}, 5000);
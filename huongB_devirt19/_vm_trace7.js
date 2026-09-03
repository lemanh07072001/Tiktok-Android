// _vm_trace7.js — Hook ALL thunk/dispatcher exit points to find VM handler dispatch
//
// The thunk at 0x9b5cc calls libc functions — NOT VM handlers.
// We need to hook the other dispatch points:
//   1. br x1 at 0x9b5e0 (thunk: ldp x1,x0,[x0]; br x1) — 61 hits
//   2. blr x8 at 0x117c68 (descriptor dispatcher: ldp x8,x0,[x0]; blr x8) — 570 hits
//   3. blr x8 at 0x1285c4 (descriptor dispatcher: ldr x8,[x0]; blr x8) — 80 hits
//   4. br x2 at 0x128604 (dispatcher: ldp x2,x8,[x0]; ldr x1,[x0,#0x10]; mov x0,x8; br x2)
//   5. blr x8 at 0x9b5f0 (thunk: ldp x8,x0,[x0]; ldr x1,[x19,#0x10]; blr x8)
//   6. br x2 at 0x9b600 (thunk: ldp x2,x8,[x0]; ldr x1,[x0,#0x10]; mov x0,x8; br x2)
//   7. blr x9 at 0x9b614 (closure-invoker: ldp x9,x8,[x0]; ldr x0,[x0,#0x10]; blr x9)
'use strict';

const SO = 'libmetasec_ov.so';
const SM3_DRV = 0x9fdac;
const RING_SZ = 2000;

// All dispatch points from thunks and descriptor dispatchers
const DISPATCH_POINTS = [
  { off: 0x9b5d8, reg: 'x3', name: 'thunk_9b5cc_br_x3' },     // br x3
  { off: 0x9b5e0, reg: 'x1', name: 'thunk_9b5dc_br_x1' },     // br x1
  { off: 0x9b5f0, reg: 'x8', name: 'thunk_9b5e4_blr_x8' },    // blr x8
  { off: 0x9b600, reg: 'x2', name: 'thunk_9b5f4_br_x2' },     // br x2
  { off: 0x9b614, reg: 'x9', name: 'thunk_9b604_blr_x9' },    // blr x9
  { off: 0x9b624, reg: 'x1', name: 'thunk_9b61c_br_x1' },     // br x1
  { off: 0x9b634, reg: 'x8', name: 'thunk_9b628_blr_x8' },    // blr x8
  { off: 0x9b644, reg: 'x1', name: 'thunk_9b63c_br_x1' },     // br x1
  { off: 0x117c68, reg: 'x8', name: 'disp_117c5c_blr_x8' },   // blr x8
  { off: 0x1285c4, reg: 'x8', name: 'disp_1285b8_blr_x8' },   // blr x8
  { off: 0x128604, reg: 'x2', name: 'disp_1285f0_br_x2' },    // br x2
];

let base = null, lo = null, hi = null;
let ring = new Array(RING_SZ);
let ri = 0;
let nHdlr = 0;
let nDrv = 0;
let dumped = false;
const MAX_DUMP = 3;

// Per-dispatch-point stats
let dpStats = {};
DISPATCH_POINTS.forEach(dp => { dpStats[dp.name] = 0; });

// Track unique handler addresses per dispatch point
let handlerSet = {};
let handlerByDP = {};
DISPATCH_POINTS.forEach(dp => { handlerByDP[dp.name] = {}; });

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

function findModuleForAddr(addr) {
  try {
    const m = Process.findModuleByAddress(addr);
    if (m) return m.name + '+0x' + addr.sub(m.base).toString(16);
  } catch(e) {}
  return null;
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
    trace: trace,
    dpStats: dpStats,
    handlerByDP: Object.entries(handlerByDP).map(([k, v]) => ({
      dp: k, unique: Object.keys(v).length, top: Object.entries(v).sort((a,b) => b[1]-a[1]).slice(0, 5)
    }))
  });
  dumped = true;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', base: base.toString(), size: m.size.toString(16),
         dpCount: DISPATCH_POINTS.length, sm3_drv: 'SELF+0x' + SM3_DRV.toString(16) });

  // ---- Hook all dispatch points ----
  for (const dp of DISPATCH_POINTS) {
    try {
      Interceptor.attach(base.add(dp.off), {
        onEnter(args) {
          const c = this.context;
          let handler = null;
          try { handler = c[dp.reg]; } catch(e) {}

          if (!handler) return;

          const handlerStr = handler.toString();
          dpStats[dp.name]++;
          handlerByDP[dp.name][handlerStr] = (handlerByDP[dp.name][handlerStr] || 0) + 1;

          const mod = findModuleForAddr(handler);
          const isSelf = inSelf(handler);

          // Only record entries that are within libmetasec_ov (VM handler range)
          // or are unknown (not in any known library)
          if (isSelf || !mod) {
            // Read x0 and x1 at dispatch point
            let x0 = null, x1 = null;
            try { x0 = c.x0; } catch(e) {}
            try { x1 = c.x1; } catch(e) {}

            let rfSlots = null;
            if (x1) {
              try { rfSlots = readRegfileSlots(x1, 8); } catch(e) {}
            }

            const rec = {
              dp: dp.name,
              h: handlerStr,
              hOff: isSelf ? selfOff(handler) : null,
              hMod: mod,
              x0: x0 ? x0.toString() : null,
              x1: x1 ? x1.toString() : null,
              rf: rfSlots
            };

            ring[ri] = rec;
            ri = (ri + 1) % RING_SZ;
            nHdlr++;
          }
        }
      });
    } catch(e) {
      send({ t: 'warn', msg: 'hook failed at ' + dp.name + ': ' + e });
    }
  }

  // ---- SM3 driver trigger ----
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

      const triggerInfo = {
        seq: nDrv,
        P: x0 ? x0.toString() : null,
        slot16: v0,
        lr: lr,
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
    onEnter(a) {
      try { this.p = a[0].readCString(); } catch(e) {}
    },
    onLeave() {
      if (this.p && this.p.indexOf(SO) >= 0) install();
    }
  });
}

setInterval(function() {
  send({ t: 'mon', nHdlr: nHdlr, nDrv: nDrv, ri: ri, dumped: dumped,
         dpStats: dpStats });
}, 5000);
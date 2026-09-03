// _vm_trace3.js — VM handler tracer via OLLVM dispatch + handler entry hooks
//
// ARCHITECTURE (from memory + live verification):
//   - 0x55950 = OLLVM-VM core: ldr x8,[x23]; add x8,x8,#4; b 0x55890
//   - 0x55890 = OLLVM dispatch: madd x8,x23,x8,x20; ldr x8,[x8]; br x8
//   - 0x5594c = MARSHALLER blr x8 (descriptor dispatchers 0x117c5c, 0x1285b8, etc.)
//   - Handlers: 0xedec0..0xf87d8 (119 distinct, 234 table entries)
//   - The br x8 at 0x55890 dispatches to ALL handlers
//
// APPROACH: Hook the dispatch br x8 at 0x55890 to capture every handler transition.
// The handler address is in x8, x0 = instr stream ptr, x1 = regfile.
// Ring buffer + SM3-driver trigger.
//
// FALLBACK: Also hook handler entry points from dispatch table (top-N most used).
'use strict';

const SO = 'libmetasec_ov.so';
const DISPATCH_BR = 0x55930;   // br x15 — OLLVM dispatch to handlers (verified: SELF+0x55930)
const SM3_DRV = 0x9fdac;       // SM3 driver trigger
const RING_SZ = 5000;

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

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', base: base.toString(), dispatch_br: 'SELF+0x' + DISPATCH_BR.toString(16),
         sm3_drv: 'SELF+0x' + SM3_DRV.toString(16) });

  // ---- Hook 1: OLLVM dispatch br x15 at 0x55930 ----
  // This is the MAIN dispatch that calls every VM handler.
  // At this point x15 = handler address, x0 = instr stream, x1 = regfile.
  Interceptor.attach(base.add(DISPATCH_BR), {
    onEnter(args) {
      const c = this.context;
      let handler = null, x0 = null, x1 = null;
      try { handler = c.x15; } catch(e) {}
      try { x0 = c.x0; } catch(e) {}
      try { x1 = c.x1; } catch(e) {}

      if (!handler) return;

      const handlerStr = selfOff(handler);

      // Read regfile slots
      let rfSlots = null;
      if (x1) {
        try { rfSlots = readRegfileSlots(x1, 8); } catch(e) {}
      }

      // Read current instr stream descriptor
      let descBytes = null;
      if (x0) {
        try { descBytes = peek(x0, 0x20); } catch(e) {}
      }

      const rec = {
        h: handlerStr,
        x0: x0 ? x0.toString() : null,
        rf: rfSlots,
        desc: descBytes
      };

      ring[ri] = rec;
      ri = (ri + 1) % RING_SZ;
      nHdlr++;
    }
  });

  // ---- Hook 2: SM3 driver trigger ----
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

      // Also read x20 (dispatch table base), x23 (stride), x19, x24
      let x19 = null, x20 = null, x23 = null, x24 = null;
      try { x19 = c.x19 ? c.x19.toString() : null; } catch(e) {}
      try { x20 = c.x20 ? c.x20.toString() : null; } catch(e) {}
      try { x23 = c.x23 ? c.x23.toString() : null; } catch(e) {}
      try { x24 = c.x24 ? c.x24.toString() : null; } catch(e) {}

      const triggerInfo = {
        seq: nDrv,
        P: x0 ? x0.toString() : null,
        slot16: v0,
        lr: lr,
        x19: x19,
        x20: x20,
        x23: x23,
        x24: x24,
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

// Install when lib loads
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

// Heartbeat
setInterval(function() {
  send({ t: 'mon', nHdlr: nHdlr, nDrv: nDrv, ri: ri, dumped: dumped });
}, 5000);
// _vm_trace5.js — Hook thunk br x3 at 0x9b5d8 to capture handler dispatch
//
// The thunk at 0x9b5cc is a simple descriptor dispatcher:
//   ldp x3, x8, [x0]         // x3=fn, x8=arg0
//   ldp x1, x2, [x0, #0x10]  // x1=len, x2=arg2
//   mov x0, x8                // x0=arg0
//   br x3                     // jump to fn
//
// The br x3 at 0x9b5d8 dispatches to the ACTUAL handler function.
// We hook this to capture the handler address in x3.
'use strict';

const SO = 'libmetasec_ov.so';
const THUNK_BR_X3 = 0x9b5d8;   // br x3 — dispatches to handler
const SM3_DRV = 0x9fdac;
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

  send({ t: 'info', base: base.toString(), thunk_br: 'SELF+0x' + THUNK_BR_X3.toString(16),
         sm3_drv: 'SELF+0x' + SM3_DRV.toString(16) });

  // ---- Hook 1: Thunk br x3 at 0x9b5d8 ----
  // At this point: x3=handler address, x0=arg0, x1=len, x2=arg2
  Interceptor.attach(base.add(THUNK_BR_X3), {
    onEnter(args) {
      const c = this.context;
      let handler = null, x0 = null, x1 = null, x2 = null;
      try { handler = c.x3; } catch(e) {}
      try { x0 = c.x0; } catch(e) {}
      try { x1 = c.x1; } catch(e) {}
      try { x2 = c.x2; } catch(e) {}

      if (!handler) return;

      const handlerStr = selfOff(handler);

      // Read arg0 as regfile
      let rfSlots = null;
      if (x1) {
        try { rfSlots = readRegfileSlots(x1, 8); } catch(e) {}
      }

      // Read 0x20 bytes at x0 (the descriptor being processed)
      let descBytes = null;
      if (x0 && x0 !== '0x0') {
        try { descBytes = peek(ptr(x0), 0x20); } catch(e) {}
      }

      const rec = {
        h: handlerStr,
        x0: x0 ? x0.toString() : null,
        x1: x1 ? x1.toString() : null,
        x2: x2 ? x2.toString() : null,
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
  send({ t: 'mon', nHdlr: nHdlr, nDrv: nDrv, ri: ri, dumped: dumped });
}, 5000);
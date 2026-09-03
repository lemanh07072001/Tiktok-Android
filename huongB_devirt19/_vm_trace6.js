// _vm_trace6.js — Hook thunk ENTRY at 0x9b5cc to capture original descriptor
// + identify which library the handler function lives in
'use strict';

const SO = 'libmetasec_ov.so';
const THUNK_ENTRY = 0x9b5cc;  // ldp x3, x8, [x0] — entry of the thunk
const THUNK_BR_X3 = 0x9b5d8;  // br x3 — exit of the thunk
const SM3_DRV = 0x9fdac;
const RING_SZ = 1000;

let base = null, lo = null, hi = null;
let ring = new Array(RING_SZ);
let ri = 0;
let nHdlr = 0;
let nDrv = 0;
let dumped = false;
const MAX_DUMP = 3;

// Track unique handler addresses
let handlerSet = {};

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
    handlerSet: Object.keys(handlerSet).slice(0, 50)
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
         thunk_entry: 'SELF+0x' + THUNK_ENTRY.toString(16),
         thunk_br: 'SELF+0x' + THUNK_BR_X3.toString(16),
         sm3_drv: 'SELF+0x' + SM3_DRV.toString(16) });

  // ---- Hook 1: Thunk ENTRY at 0x9b5cc ----
  // At entry: x0 = descriptor address
  Interceptor.attach(base.add(THUNK_ENTRY), {
    onEnter(args) {
      const c = this.context;
      let descX0 = null;
      try { descX0 = c.x0; } catch(e) {}

      if (!descX0) return;

      // Read the function pointer from the descriptor ([x0])
      let fnPtr = null, arg0 = null;
      try {
        fnPtr = descX0.readPointer();
        arg0 = descX0.add(8).readPointer();
      } catch(e) {}

      const fnStr = fnPtr ? fnPtr.toString() : '0';
      const mod = fnPtr ? findModuleForAddr(fnPtr) : null;

      // Track unique handlers
      handlerSet[fnStr] = (handlerSet[fnStr] || 0) + 1;

      // Read descriptor
      let descBytes = null;
      try { descBytes = peek(descX0, 0x20); } catch(e) {}

      const rec = {
        h: fnStr,
        hMod: mod,
        hOff: fnPtr && inSelf(fnPtr) ? 'SELF+0x' + fnPtr.sub(base).toString(16) : null,
        descX0: descX0.toString(),
        arg0: arg0 ? arg0.toString() : null,
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

      // Capture x15/x20/x23 for OLLVM context
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
        ri: ri,
        uniqueHandlers: Object.keys(handlerSet).length
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
         uniqueHandlers: Object.keys(handlerSet).length });
}, 5000);
// _vm_trace.js — VM record-stream tracer for slot16 producer
//
// GOAL: capture the VM execution trace that produces slot16, by hooking the centralized
// VM dispatch at 0x5594c (blr x8). A ring buffer records the last N instructions. When
// the SM3-driver 0x9fdac fires with w1=16 (slot16 hash), the ring buffer is dumped.
//
// VM model (from _vm_dispatch_table.json):
//   x0  = threaded instr-stream ptr (each handler ends with: ldr x4,[x0,#0x20]!; br x4)
//   x1  = VM register file (8-byte slots, indexed [x1, idx, lsl#3])
//   x20 = dispatch table base (rebased 0x1d9488)
//   x23 = opcode/PC stride
//
// Dispatch at 0x5594c: blr x8 — x8 = handler target address
// The handler thunks are in the range SELF+0x9b5cc..0x9b7c8
// Actual handlers are in 0xedec0..0xf87d8
//
// Ring buffer: 3000 entries, each recording:
//   - handler target address (identifies the opcode)
//   - x0 (instr stream ptr — shows where we are in the bytecode)
//   - x1 (regfile base)
//   - regfile slot 29 (known to hold ratchet/key material from prior notes)
//   - regfile slots 0-7 (first 8 slots, most commonly used)
//
// Trigger: SM3-driver 0x9fdac fires with w1==16 and slot16 is nonzero
//   → dump entire ring buffer as JSON
//   → also dump FULL regfile (first 64 slots) at trigger point
//
// Oracle values (for verification):
//   46c03b52742b3f2615a3abdf1636b754 — cross-device constant
//   ff9fe53b... — known from prior captures
//   6df68ced... — known from prior captures
'use strict';

const SO = 'libmetasec_ov.so';
const VM_DISPATCH = 0x5594c;   // blr x8 — centralized VM dispatch
const SM3_DRV = 0x9fdac;       // SM3 driver — our trigger
const RING_SZ = 3000;           // ring buffer size
const REGFILE_SLOTS = 8;        // how many regfile slots to snapshot per instruction

let base = null, lo = null, hi = null;
let ring = new Array(RING_SZ);
let ri = 0;                     // ring write index
let nVm = 0;                    // total VM instructions seen
let nDrv = 0;                   // SM3 driver calls seen
let dumped = false;             // only dump once
const MAX_DRV = 3;              // capture up to 3 slot16 cycles

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
  // rf = x1 = register file base pointer
  // Returns array of hex strings, one per slot
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

function readFullRegfile(rf, nSlots) {
  const slots = [];
  for (let i = 0; i < nSlots; i++) {
    try {
      const addr = rf.add(i * 8);
      slots.push(hx(addr.readByteArray(8)));
    } catch(e) {
      break;
    }
  }
  return slots;
}

function dumpRing(triggerInfo) {
  // Dump ring buffer: entries from (ri - RING_SZ) to (ri - 1), wrapping around
  const trace = [];
  const start = (ri - RING_SZ + RING_SZ) % RING_SZ;  // actually: ri is the OLDEST entry
  // Wait, let me reconsider. ri is the NEXT write position. So the valid entries
  // are from ri (oldest if buffer is full) to (ri-1+RING_SZ)%RING_SZ (newest).
  // If the buffer isn't full yet (nVm < RING_SZ), entries are at indices 0..ri-1.

  const total = Math.min(nVm, RING_SZ);
  for (let i = 0; i < total; i++) {
    const idx = (ri - total + i + RING_SZ) % RING_SZ;
    const entry = ring[idx];
    if (entry) trace.push(entry);
  }

  const dump = {
    t: 'VM_TRACE_DUMP',
    trigger: triggerInfo,
    nVm: nVm,
    traceLen: trace.length,
    trace: trace
  };

  send(dump);
  dumped = true;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);
  send({ t: 'info', base: base.toString(), vm_dispatch: 'SELF+0x' + VM_DISPATCH.toString(16),
         sm3_drv: 'SELF+0x' + SM3_DRV.toString(16), ringSz: RING_SZ });

  // ---- Hook 1: VM dispatch (blr x8 at 0x5594c) ----
  Interceptor.attach(base.add(VM_DISPATCH), {
    onEnter(args) {
      // At this point, x8 holds the handler target address
      const c = this.context;
      let handler = null;
      try { handler = c.x8; } catch(e) {}
      if (!handler) return;

      const handlerStr = selfOff(handler);
      let x0 = null, x1 = null, x0Str = null;
      try { x0 = c.x0; x0Str = x0 ? x0.toString() : null; } catch(e) {}
      try { x1 = c.x1; } catch(e) {}

      // Snapshot a few key regfile slots
      let rfSlots = null;
      if (x1) {
        rfSlots = readRegfileSlots(x1, REGFILE_SLOTS);
      }

      // Record
      const rec = {
        h: handlerStr,        // handler address
        x0: x0Str,            // instr stream ptr
        rf: rfSlots           // regfile slots 0..7
      };

      ring[ri] = rec;
      ri = (ri + 1) % RING_SZ;
      nVm++;
    }
  });

  // ---- Hook 2: SM3 driver (trigger at 0x9fdac) ----
  Interceptor.attach(base.add(SM3_DRV), {
    onEnter(args) {
      if (dumped) return;
      if (nDrv >= MAX_DRV) return;

      const c = this.context;
      let w1 = null;
      try { w1 = parseInt(c.x1.toString()) & 0xffffffff; } catch(e) {}
      if (w1 !== 16) return;  // only slot16 calls

      // Check slot16 is nonzero
      const x0 = c.x0;
      const v0 = x0 ? peek(x0, 16) : null;
      if (!v0 || v0 === '00000000000000000000000000000000') return;

      nDrv++;

      // Read full regfile at trigger point
      let fullRf = null;
      try { fullRf = readFullRegfile(c.x1, 64); } catch(e) {}

      // Read additional context
      let x2 = null, x19 = null, x20 = null, x23 = null, x24 = null;
      try { x2 = c.x2 ? c.x2.toString() : null; } catch(e) {}
      try { x19 = c.x19 ? c.x19.toString() : null; } catch(e) {}
      try { x20 = c.x20 ? c.x20.toString() : null; } catch(e) {}
      try { x23 = c.x23 ? c.x23.toString() : null; } catch(e) {}
      try { x24 = c.x24 ? c.x24.toString() : null; } catch(e) {}

      let lr = null;
      try { lr = selfOff(c.lr); } catch(e) {}

      // Also read the SM3 digest context (x2 = 32-byte SM3 context)
      const digestCtx = x2 ? peek(c.x2, 32) : null;

      const triggerInfo = {
        seq: nDrv,
        P: x0 ? x0.toString() : null,
        slot16: v0,
        x1: c.x1 ? c.x1.toString() : null,
        x2: x2,
        x19: x19,
        x20: x20,
        x23: x23,
        x24: x24,
        lr: lr,
        digestCtx: digestCtx,
        fullRf: fullRf,           // full regfile at trigger
        nVm: nVm,
        ri: ri
      };

      send({ t: 'TRIGGER', info: triggerInfo });

      // Dump the ring buffer
      dumpRing(triggerInfo);
    }
  });

  send({ t: 'ready' });
  return true;
}

// ---- Install when libmetasec_ov.so loads ----
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

// ---- Heartbeat ----
setInterval(function() {
  send({ t: 'mon', nVm: nVm, nDrv: nDrv, ri: ri, dumped: dumped });
}, 5000);
/*
 * _vm_trace10.js — CORRECTED VM tracer (v2)
 *
 * TASK D: VM record-stream tracer (ring buffer, trigger at SM3-driver)
 * → trích program slot16 → lift → diff oracle
 *
 * FIXES from v1:
 *   1. TRACE_DUMP sent BEFORE TRIGGER (survives register-read crashes)
 *   2. All register reads in trigger are try/catch safe
 *   3. 0x55898 is movk x9, NOT br x8 — removed that hook entirely
 *   4. Only correct dispatch point: br x15 @ 0x55930 (VM handler dispatch)
 *   5. SM3 driver trigger @ 0x9fdac: dump ring buffer on SM3 entry
 *   6. w1 == 16 filter (slot16 trigger)
 *
 * Architecture:
 *   - x23: pointer to VM PC (bytecode instruction pointer)
 *   - x24: register file base pointer (array of 2 bank pointers)
 *   - x15: handler dispatch target (adjusted handler address)
 *   - br x15 @ 0x55930: the ONLY VM handler dispatch
 *
 * Usage:
 *   python3 _run_probe.py _vm_trace10.js
 */
'use strict';

const SO = 'libmetasec_ov.so';
const BR_X15_DISP = 0x55930;  // br x15 — VM handler dispatch
const SM3_DRV_ENTRY = 0x9fdac; // SM3 driver entry

let base = null, lo = null, hi = null;

const RING_SIZE = 2048;
const ring = [];
let ringIdx = 0;
let seq = 0;
let nDrv = 0;
let dumped = false;
const MAX_DUMP = 1;

function inSelf(p) {
  try { return p.compare(lo) >= 0 && p.compare(hi) < 0; } catch(e) { return false; }
}

function selfOff(p) {
  try {
    if (inSelf(p)) return p.sub(base).toInt32();
  } catch(e) {}
  return -1;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', msg: 'libmetasec loaded', base: base.toString() });

  // ── Hook 1: br x15 dispatch ────────────────────────────────────────
  Interceptor.attach(base.add(BR_X15_DISP), {
    onEnter(args) {
      if (dumped) return;
      const ctx = this.context;
      const handlerOff = selfOff(ctx.x15);
      if (handlerOff < 0) return;

      // Read bytecode pointer from *x23
      let bytecodeOff = -1, insnWord = 0, nextInsnWord = 0;
      try {
        const x23 = ctx.x23;
        const bcPtr = x23.readPointer();
        bytecodeOff = bcPtr.sub(base).toInt32();
        insnWord = bcPtr.readU32();
        nextInsnWord = bcPtr.add(4).readU32();
      } catch(e) {}

      // Read register file — x24 points to array of bank pointers
      let regs = {};
      try {
        const x24 = ctx.x24;
        const bank0 = x24.readPointer();
        const bank1 = x24.add(8).readPointer();
        for (let i = 0; i < 4; i++) {
          try { regs['r' + i] = bank0.add(i * 8).readU64().toString(16); } catch(e) {}
        }
        for (let i = 0; i < 4; i++) {
          try { regs['r' + (16 + i)] = bank1.add(i * 8).readU64().toString(16); } catch(e) {}
        }
      } catch(e) {}

      ring[ringIdx % RING_SIZE] = {
        seq: seq++,
        h: handlerOff,
        bc: bytecodeOff,
        iw: insnWord,
        niw: nextInsnWord,
        op: insnWord & 0x3f,
        nop: nextInsnWord & 0x3f,
        r: regs,
        x0: ctx.x0.toString(),
        x1: ctx.x1.toString(),
        x2: ctx.x2.toString(),
        x3: ctx.x3.toString(),
      };
      ringIdx++;
    }
  });

  // ── Hook 2: SM3 driver trigger ─────────────────────────────────────
  Interceptor.attach(base.add(SM3_DRV_ENTRY), {
    onEnter(args) {
      if (dumped) return;
      if (nDrv >= MAX_DUMP) return;

      const ctx = this.context;
      let w1 = null;
      try { w1 = parseInt(ctx.x1.toString()) & 0xffffffff; } catch(e) {}
      if (w1 !== 16) return;

      // Verify slot16 is non-zero
      const x0 = ctx.x0;
      try {
        const bytes = x0.readByteArray(16);
        const u8 = new Uint8Array(bytes);
        let allZero = true;
        for (let i = 0; i < 16; i++) { if (u8[i] !== 0) { allZero = false; break; } }
        if (allZero) return;
      } catch(e) { return; }

      nDrv++;
      dumped = true;

      // ── DUMP RING BUFFER FIRST (survives register-read crashes) ──
      const start = Math.max(0, ringIdx - RING_SIZE);
      const end = ringIdx;
      const entries = [];
      for (let i = start; i < end; i++) {
        const e = ring[i % RING_SIZE];
        if (e) entries.push(e);
      }
      send({ t: 'TRACE_DUMP', count: entries.length, entries: entries });

      // ── TRIGGER info (best-effort, all reads safe) ──
      let slot16hex = null;
      try { slot16hex = hex(x0.readByteArray(16)); } catch(e) {}
      let lr = null, x0s = null, x1s = null, x2s = null, x3s = null;
      let x22s = null, x23s = null, x24s = null, x29s = null, x30s = null;
      try { lr = selfOff(ctx.lr); } catch(e) {}
      try { x0s = ctx.x0 ? ctx.x0.toString() : null; } catch(e) {}
      try { x1s = ctx.x1 ? ctx.x1.toString() : null; } catch(e) {}
      try { x2s = ctx.x2 ? ctx.x2.toString() : null; } catch(e) {}
      try { x3s = ctx.x3 ? ctx.x3.toString() : null; } catch(e) {}
      try { x22s = ctx.x22 ? ctx.x22.toString() : null; } catch(e) {}
      try { x23s = ctx.x23 ? ctx.x23.toString() : null; } catch(e) {}
      try { x24s = ctx.x24 ? ctx.x24.toString() : null; } catch(e) {}
      try { x29s = ctx.x29 ? ctx.x29.toString() : null; } catch(e) {}
      try { x30s = ctx.x30 ? ctx.x30.toString() : null; } catch(e) {}

      send({
        t: 'TRIGGER',
        slot16: slot16hex,
        lr: lr,
        x0: x0s,
        x1: x1s,
        x2: x2s,
        x3: x3s,
        x22: x22s,
        x23: x23s,
        x24: x24s,
        x29: x29s,
        x30: x30s,
      });
    }
  });

  send({ t: 'ready' });
  return true;
}

function hex(ab) {
  const u = new Uint8Array(ab);
  let s = '';
  for (let i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
  return s;
}

// ── Bootstrap: wait for libmetasec_ov.so to load ──────────────────────
if (Process.findModuleByName(SO)) {
  install();
} else {
  // Poll for library load
  const tryInstall = () => {
    if (Process.findModuleByName(SO)) {
      install();
    } else {
      setTimeout(tryInstall, 200);
    }
  };
  setTimeout(tryInstall, 500);
}

// Heartbeat
setInterval(function() {
  send({ t: 'mon', seq: seq, dumped: dumped });
}, 5000);
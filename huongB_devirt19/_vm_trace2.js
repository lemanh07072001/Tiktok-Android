// _vm_trace2.js — VM handler tracer via ldr x4,[x0,#0x20]!; br x4 pattern scan
//
// KEY INSIGHT: The blr x8 at 0x5594c calls DESCRIPTOR DISPATCHERS (0x117c5c, 0x9b5cc, etc.),
// NOT the VM handlers. The VM handlers (0xedec0..0xf87d8) are dispatched through the
// instruction stream via ldr x4,[x0,#0x20]!; br x4.
//
// This script SCANS the handler range for the pattern and hooks the br x4 instructions.
// Each hook captures the handler address, x0 (instr stream ptr), and x1 (regfile).
//
// Ring buffer records the last N handler transitions. When the SM3-driver fires with
// w1=16, the ring buffer is dumped.
'use strict';

const SO = 'libmetasec_ov.so';
const SM3_DRV = 0x9fdac;       // SM3 driver trigger
const RING_SZ = 5000;           // ring buffer

// Handler range (from dispatch table)
const HANDLER_LO = 0xedec0;
const HANDLER_HI = 0xf87d8;
const LDR_X4_PATTERN = 0xf8420c04;  // ldr x4,[x0,#0x20]! (verified from binary)
const BR_X4 = 0xd61f0080;           // br x4

let base = null, lo = null, hi = null;
let ring = new Array(RING_SZ);
let ri = 0;
let nHdlr = 0;                    // handler transitions seen
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

function scanAndHookHandlers() {
  const m = Process.findModuleByName(SO);
  if (!m) return 0;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  const handlerStart = base.add(HANDLER_LO);
  const handlerEnd = base.add(HANDLER_HI);
  const size = HANDLER_HI - HANDLER_LO;

  send({ t: 'info', msg: 'scanning handler range ' +
    'SELF+0x' + HANDLER_LO.toString(16) + '..SELF+0x' + HANDLER_HI.toString(16) +
    ' (' + size + ' bytes)' });

  let hooksInstalled = 0;

  try {
    const code = handlerStart.readByteArray(size);
    const u8 = new Uint8Array(code);

    for (let i = 0; i < u8.length - 8; i++) {
      // Read 4 bytes as uint32 (little-endian), use >>> 0 to force unsigned
      const ins = (u8[i] | (u8[i+1] << 8) | (u8[i+2] << 16) | (u8[i+3] << 24)) >>> 0;

      if (ins === LDR_X4_PATTERN) {
        // Check next instruction is br x4
        const nextIns = (u8[i+4] | (u8[i+5] << 8) | (u8[i+6] << 16) | (u8[i+7] << 24)) >>> 0;
        if (nextIns === BR_X4) {
          const brAddr = handlerStart.add(i + 4);
          const ldrAddr = handlerStart.add(i);
          const ldrOff = HANDLER_LO + i;
          const brOff = HANDLER_LO + i + 4;

          // Hook the br x4 instruction
          try {
            Interceptor.attach(brAddr, {
              onEnter(args) {
                const c = this.context;
                let x4 = null, x0 = null, x1 = null;
                try { x4 = c.x4; } catch(e) {}
                try { x0 = c.x0; } catch(e) {}
                try { x1 = c.x1; } catch(e) {}

                // Read regfile slots
                let rfSlots = null;
                if (x1) {
                  try { rfSlots = readRegfileSlots(x1, 8); } catch(e) {}
                }

                // Read previous descriptor (at x0 - 0x20) to get current handler info
                let prevDesc = null;
                if (x0) {
                  try {
                    const prevAddr = x0.sub(0x20);
                    prevDesc = hx(prevAddr.readByteArray(0x20));
                  } catch(e) {}
                }

                const rec = {
                  h: selfOff(x4),              // NEXT handler address
                  prev: selfOff(ldrAddr),      // CURRENT handler (this br x4's context)
                  x0: x0 ? x0.toString() : null, // instr stream ptr (advanced)
                  rf: rfSlots,                  // regfile slots
                  desc: prevDesc,               // previous descriptor
                  ldrOff: 'SELF+0x' + ldrOff.toString(16),
                  brOff: 'SELF+0x' + brOff.toString(16)
                };

                ring[ri] = rec;
                ri = (ri + 1) % RING_SZ;
                nHdlr++;
              }
            });
            hooksInstalled++;
          } catch(e) {
            send({ t: 'warn', msg: 'hook failed at SELF+0x' + brOff.toString(16) + ': ' + e });
          }
        }
      }
    }
  } catch(e) {
    send({ t: 'error', msg: 'scan failed: ' + e });
    return 0;
  }

  send({ t: 'info', msg: 'installed ' + hooksInstalled + ' br x4 hooks in handler range' });
  return hooksInstalled;
}

function install() {
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base;
  lo = base;
  hi = base.add(m.size);

  send({ t: 'info', base: base.toString(), sm3_drv: 'SELF+0x' + SM3_DRV.toString(16) });

  // Scan and hook handlers
  const nHooks = scanAndHookHandlers();
  if (nHooks === 0) {
    send({ t: 'error', msg: 'NO handler hooks installed! Pattern scan failed.' });
    return false;
  }

  // Hook SM3 driver as trigger
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

      // Read full regfile at trigger point
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

  send({ t: 'ready', hooks: nHooks });
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
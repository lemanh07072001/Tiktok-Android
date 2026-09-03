/*
 * _vm_trace11.js — VM tracer v3 (CORRECTED register file)
 *
 * TASK D: record-stream tracer → trích program slot16 → lift → diff oracle
 *
 * FIX vs v2 (_vm_trace10.js): register file is FLAT at x24, reg[i]=[x24+i*8].
 *   Disasm-confirmed:
 *     0x55854  str x8,[x24,w28,uxtw#3]   ; regfile[idx]=x8
 *     0x55878  ldr x8,[x24,w22,uxtw#3]
 *     op40     ldr x16,[x24,x25,lsl#3] / str x16,[x24,x12,lsl#3]
 *   v2 wrongly treated x24 as array-of-2-bank-pointers (double deref → read code).
 *
 * VM model (disasm 0x55890..0x5596c):
 *   x23 -> holds PC; *x23=PC; insn=[PC]; op=insn&0x3f; PC+=4 each step.
 *   x24 = flat register file base (32 regs, 5-bit index fields).
 *   x15 = real handler VMA; br x15 @0x55930 = the ONLY dispatch.
 */
'use strict';

const SO = 'libmetasec_ov.so';
const BR_X15_DISP = 0x55930;
const SM3_DRV_ENTRY = 0x9fdac;
const RING_SIZE = 4096;
const NREG = 32;
const CHUNK = 100;

let base = null, lo = null, hi = null;
const ring = [];
let ringIdx = 0, seq = 0, nDrv = 0, dumped = false;
const MAX_DUMP = 1;

function inSelf(p){ try { return p.compare(lo) >= 0 && p.compare(hi) < 0; } catch(e){ return false; } }
function selfOff(p){ try { if (inSelf(p)) return p.sub(base).toInt32(); } catch(e){} return -1; }
function hex(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }

function readRF(x24){
  const rf = new Array(NREG).fill(null);
  try {
    for (let i = 0; i < NREG; i++) {
      try { rf[i] = x24.add(i*8).readU64().toString(16); } catch(e){}
    }
  } catch(e){}
  return rf;
}

function install(){
  const m = Process.findModuleByName(SO);
  if (!m) return false;
  base = m.base; lo = base; hi = base.add(m.size);
  send({ t:'info', msg:'libmetasec loaded', base:base.toString() });

  // Hook 1: VM dispatch
  Interceptor.attach(base.add(BR_X15_DISP), {
    onEnter(){
      if (dumped) return;
      const ctx = this.context;
      const handlerOff = selfOff(ctx.x15);
      if (handlerOff < 0) return;
      let bc = -1, iw = 0, niw = 0;
      try {
        const pc = ctx.x23.readPointer();
        bc = pc.sub(base).toInt32();
        iw = pc.readU32();
        niw = pc.add(4).readU32();
      } catch(e){}
      ring[ringIdx % RING_SIZE] = {
        seq: seq++, h: handlerOff, bc: bc, iw: iw, niw: niw,
        op: iw & 0x3f, rf: readRF(ctx.x24)
      };
      ringIdx++;
    }
  });

  // Hook 2: SM3 driver trigger (slot16 consumption)
  Interceptor.attach(base.add(SM3_DRV_ENTRY), {
    onEnter(){
      if (dumped) return;
      if (nDrv >= MAX_DUMP) return;
      const ctx = this.context;
      let w1 = null; try { w1 = parseInt(ctx.x1.toString()) & 0xffffffff; } catch(e){}
      if (w1 !== 16) return;
      const x0 = ctx.x0;
      try {
        const u8 = new Uint8Array(x0.readByteArray(16));
        let z = true; for (let i=0;i<16;i++){ if(u8[i]!==0){ z=false; break; } }
        if (z) return;
      } catch(e){ return; }
      nDrv++; dumped = true;

      let slot16 = null; try { slot16 = hex(x0.readByteArray(16)); } catch(e){}
      const g = (r)=>{ try { return ctx[r] ? ctx[r].toString() : null; } catch(e){ return null; } };
      send({
        t:'TRIGGER', slot16: slot16, lr: selfOff(ctx.lr),
        x0:g('x0'), x1:g('x1'), x2:g('x2'), x3:g('x3'),
        x22:g('x22'), x23:g('x23'), x24:g('x24'),
        rf: readRF(ctx.x24)
      });

      const start = Math.max(0, ringIdx - RING_SIZE), end = ringIdx;
      const all = [];
      for (let i = start; i < end; i++){ const e = ring[i % RING_SIZE]; if (e) all.push(e); }
      let sent = 0;
      for (let i = 0; i < all.length; i += CHUNK){
        const part = all.slice(i, i+CHUNK);
        send({ t:'TRACE_DUMP', idx:i, total:all.length, count:part.length, entries:part });
        sent += part.length;
      }
      send({ t:'done', total: all.length, sent: sent });
    }
  });

  send({ t:'ready' });
  return true;
}

if (Process.findModuleByName(SO)) install();
else { const tryI=()=>{ if (Process.findModuleByName(SO)) install(); else setTimeout(tryI,200); }; setTimeout(tryI,500); }
setInterval(()=>send({ t:'mon', seq:seq, dumped:dumped }), 5000);

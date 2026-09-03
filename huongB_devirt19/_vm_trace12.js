/*
 * _vm_trace12.js — PRODUCER CENSUS (v12)
 *
 * Hypothesis: slot16 producer runs via blr x8 @0xa02a8 (x0=x21 ctx, x1=x23 input),
 * possibly BEFORE the SM3-consume window. Goal:
 *   1. Census EVERY 0xa02a8 call: callId, resolved target, ctx(x21), input(x23), input snapshot.
 *   2. Count br-x15 dispatches per call (program size => marshaller vs producer).
 *   3. At SM3-consume: capture V(slot16) + B(buffer ptr). Then find which prior call's
 *      ctx holds a pointer == B  =>  offset of slot16-buffer-ptr inside ctx (stable slot).
 *   4. Backtrace on first 0xa02a8 call (caller chain).
 *
 * Emits everything; correlation done offline.
 */
'use strict';
const SO = 'libmetasec_ov.so';
const BLR_X8   = 0xa02a8;   // blr x8 — suspected producer/VM call
const BR_X15   = 0x55930;   // VM handler dispatch
const SM3_DRV  = 0x9fdac;   // SM3 driver entry (slot16 consumer)

let base=null, lo=null, hi=null;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return p.sub(base).toInt32(); }catch(e){} return -1; }
function hexBytes(p,n){ try{ const u=new Uint8Array(p.readByteArray(n)); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }

let callId=0;
let curDispCount=0;
let dumped=false;
const MAX_CALLS_KEEP = 64;
const calls = [];            // ring of recent 0xa02a8 calls
let btDone=false;

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', msg:'libmetasec loaded', base:base.toString()});

  // Hook A: producer/VM call site
  Interceptor.attach(base.add(BLR_X8), {
    onEnter(a){
      if(dumped) return;
      const c=this.context;
      // finalize previous call's dispatch count
      if(calls.length>0){ calls[calls.length-1].disp = curDispCount; }
      curDispCount=0;
      const tgt = selfOff(c.x8);
      const rec = {
        id: callId++,
        tgt: tgt,
        ctx: c.x21 ? c.x21.toString() : null,     // x0 = x21
        inp: c.x23 ? c.x23.toString() : null,     // x1 = x23
        inSnap: c.x23 ? hexBytes(c.x23, 64) : null,
        // snapshot a chunk of ctx to search later for the slot16 buffer ptr
        ctxSnap: c.x21 ? hexBytes(c.x21, 256) : null,
        disp: 0,
      };
      calls.push(rec);
      if(calls.length>MAX_CALLS_KEEP) calls.shift();
      if(!btDone){
        btDone=true;
        try{
          const bt = Thread.backtrace(c, Backtracer.ACCURATE).map(selfOff);
          send({t:'BT', callId:rec.id, bt:bt});
        }catch(e){}
      }
    }
  });

  // Hook B: dispatch counter (light)
  Interceptor.attach(base.add(BR_X15), {
    onEnter(a){ if(dumped) return; curDispCount++; }
  });

  // Hook C: SM3 consume — trigger + correlate
  Interceptor.attach(base.add(SM3_DRV), {
    onEnter(a){
      if(dumped) return;
      const c=this.context;
      let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
      if(w1!==16) return;
      const B=c.x0;
      const V=hexBytes(B,16); if(!V || V==='00000000000000000000000000000000') return;
      dumped=true;
      if(calls.length>0){ calls[calls.length-1].disp = curDispCount; }
      const Bstr = B.toString();
      // offline correlation payload
      send({t:'SM3', slot16:V, buf:Bstr, bufNbr:hexBytes(B.sub(32),96),
            lr:selfOff(c.lr), nCalls:callId,
            calls: calls.slice() });
    }
  });

  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,200); }; setTimeout(t,300); }
setInterval(function(){ send({t:'mon', calls:callId, disp:curDispCount, dumped:dumped}); }, 5000);

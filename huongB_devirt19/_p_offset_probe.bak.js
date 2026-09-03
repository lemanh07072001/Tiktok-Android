/*
 * _p_offset_probe.js — MEASURE where slot16 P lives (route P, catch-at-birth prep)
 *
 * Thesis (static 2026-08-29a): VM = orchestrator; P's buffer is allocated via
 * operator new (_Znwm/_Znam), NOT libc malloc → prior allocator-hook missed it.
 *
 * This probe (MEASUREMENT ONLY, no WP, no re-register):
 *   1. Hook _Znwm/_Znam globally, but only RECORD allocations whose returnAddress
 *      ∈ libmetasec_ov.so (i.e. the library's own C++ allocations). Ring of last N.
 *   2. Hook SM3 driver 0x9fdac; when w1==16 && slot16 nonzero, x0 = P pointer.
 *      Find the most-recent recorded libmetasec buffer containing x0.
 *      Emit {slot16, P, buf, size, offset=P-buf, callsite}.
 *   Goal: is (callsite, offset, size) STABLE across triggers? If yes → next run
 *   we can arm a precise WP at buf+offset at birth to catch the producer PC.
 */
'use strict';
const SO='libmetasec_ov.so';
const SM3_DRV=0x9fdac;
const RING=1024;
let base=null,lo=null,hi=null,ready=false;
const ring=new Array(RING); let ri=0;
let nTrig=0; const MAXTRIG=8;

function inSelf(p){ try{return p.compare(lo)>=0&&p.compare(hi)<0;}catch(e){return false;} }
function off(p){ try{ if(inSelf(p)) return p.sub(base).toInt32(); }catch(e){} return -1; }

function hookNew(name){
  const a=Module.findGlobalExportByName(name);
  if(!a){ send({t:'info',msg:'no export '+name}); return; }
  Interceptor.attach(a,{
    onEnter(args){ this.sz=args[0].toInt32(); this.ra=this.returnAddress; },
    onLeave(ret){
      const r=this.ra;
      if(!r||r.compare(lo)<0||r.compare(hi)>=0) return; // only libmetasec callers
      ring[ri%RING]={buf:ret,size:this.sz,cs:r.sub(base).toInt32(),name:name};
      ri++;
    }
  });
  send({t:'info',msg:'hooked '+name+' @'+a});
}

function install(){
  const m=Process.findModuleByName(SO);
  if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',msg:'libmetasec base='+base});
  hookNew('_Znwm'); hookNew('_Znam');
  Interceptor.attach(base.add(SM3_DRV),{
    onEnter(args){
      if(nTrig>=MAXTRIG) return;
      const ctx=this.context;
      let w1=-1; try{ w1=parseInt(ctx.x1.toString())&0xffffffff; }catch(e){}
      if(w1!==16) return;
      const x0=ctx.x0;
      let bytes=null; try{ bytes=new Uint8Array(x0.readByteArray(16)); }catch(e){ return; }
      let allz=true; for(let i=0;i<16;i++) if(bytes[i]!==0){allz=false;break;}
      if(allz) return;
      let s=''; for(let i=0;i<16;i++) s+=('0'+bytes[i].toString(16)).slice(-2);
      // find containing buffer (most recent first)
      let found=null;
      for(let k=ri-1;k>=Math.max(0,ri-RING);k--){
        const e=ring[k%RING]; if(!e) continue;
        try{
          const bend=e.buf.add(e.size);
          if(x0.compare(e.buf)>=0 && x0.compare(bend)<0){
            found={buf:e.buf.toString(),size:e.size,cs:e.cs,name:e.name,offset:x0.sub(e.buf).toInt32()};
            break;
          }
        }catch(ex){}
      }
      nTrig++;
      send({t:'HIT',n:nTrig,slot16:s,P:x0.toString(),lr:off(ctx.lr),ring:ri,found:found});
    }
  });
  ready=true; send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150); }; setTimeout(f,300); }
setInterval(()=>send({t:'mon',ring:ri,trig:nTrig}),4000);

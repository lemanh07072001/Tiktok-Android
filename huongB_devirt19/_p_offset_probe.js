/*
 * _p_offset_probe.js v2 — MEASURE where slot16 P lives (route P, catch-at-birth prep)
 *
 * FIXES v2:
 *  - Install SM3-driver TRIGGER hook FIRST (so a bad new-hook can't kill it).
 *  - try/catch around each Interceptor.attach (frida17 _Znam @libc++ was un-interceptable).
 *  - nAll[name] diagnostic: total onEnter count BEFORE the return-addr filter, so we can
 *    tell "libmetasec never calls _Znwm" (nAll=0) apart from "filter rejects all" (nAll>0,ring=0).
 */
'use strict';
const SO='libmetasec_ov.so';
const SM3_DRV=0x9fdac;
const RING=1024;
let base=null,lo=null,hi=null;
const ring=new Array(RING); let ri=0;
let nTrig=0; const MAXTRIG=8;
const nAll={};        // total calls seen per allocator
const nSelf={};       // calls with returnAddress in libmetasec

function inSelf(p){ try{return p.compare(lo)>=0&&p.compare(hi)<0;}catch(e){return false;} }
function off(p){ try{ if(inSelf(p)) return p.sub(base).toInt32(); }catch(e){} return -1; }

function hookNew(name){
  let a=null;
  try{ a=Module.findGlobalExportByName(name); }catch(e){}
  if(!a){ send({t:'info',msg:'no export '+name}); return; }
  nAll[name]=0; nSelf[name]=0;
  try{
    Interceptor.attach(a,{
      onEnter(args){ this.sz=args[0].toInt32(); this.ra=this.returnAddress; nAll[name]++; },
      onLeave(ret){
        const r=this.ra;
        if(!r||r.compare(lo)<0||r.compare(hi)>=0) return; // only libmetasec callers
        nSelf[name]++;
        ring[ri%RING]={buf:ret,size:this.sz,cs:r.sub(base).toInt32(),name:name};
        ri++;
      }
    });
    send({t:'info',msg:'hooked '+name+' @'+a});
  }catch(e){ send({t:'info',msg:'FAILED hook '+name+': '+e}); }
}

function install(){
  const m=Process.findModuleByName(SO);
  if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',msg:'libmetasec base='+base});

  // TRIGGER FIRST — never let allocator-hook failures suppress it
  try{
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
        send({t:'HIT',n:nTrig,slot16:s,P:x0.toString(),lr:off(ctx.lr),ring:ri,found:found,nAll:nAll,nSelf:nSelf});
      }
    });
    send({t:'info',msg:'hooked SM3 driver @0x'+SM3_DRV.toString(16)});
  }catch(e){ send({t:'info',msg:'FAILED SM3 hook: '+e}); }

  hookNew('_Znwm'); hookNew('_Znam');
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,150); }; setTimeout(f,300); }
setInterval(()=>send({t:'mon',ring:ri,trig:nTrig,nAll:nAll,nSelf:nSelf}),4000);

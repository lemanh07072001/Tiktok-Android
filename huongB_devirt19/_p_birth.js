/*
 * _p_birth.js v2 — catch P container at ALLOCATION via libc EXPORT hooks
 *                  with an ultra-cheap caller∈libmetasec filter.
 *
 * PLT-stub hooking failed (Frida can't relocate the adrp/br thunk). So hook
 * the real malloc/_Znwm exports, but the FIRST thing onEnter does is a 2-ptr
 * range compare on returnAddress; non-libmetasec callers bail instantly →
 * overhead tiny vs global memcpy hook → init/heartbeat burst should survive.
 *
 * Ring-buffer every libmetasec-origin chunk. At SM3-driver (0x9fd98) with
 * len==16 and nonzero slot16, find the ring chunk CONTAINING P:
 *   BIRTH   → {allocFn, callsite, chunkSize, P-offset}  (producer target known)
 *   NOCHUNK → P from long-lived/other alloc (persistent session struct)
 */
'use strict';
const SO='libmetasec_ov.so';
const OFF_DRIVER=0x9fd98;
let base=null, lo=null, hi=null;
const RING=8192; const ring=new Array(RING); let ri=0;
let nAlloc=0, nDrv=0, hits=0; const MAXHIT=14;

function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ return inSelf(p) ? '+0x'+p.sub(base).toString(16) : (p?p.toString():'?'); }
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }

function hookAlloc(name, fn, szIdx){
  const a=Module.findGlobalExportByName(name); if(!a){ send({t:'warn',msg:'no '+name}); return; }
  Interceptor.attach(a,{
    onEnter(args){
      if(!inSelf(this.returnAddress)){ this.skip=true; return; }   // cheap filter FIRST
      this.skip=false; this.sz=parseInt(args[szIdx].toString())|0; this.cs=this.returnAddress;
    },
    onLeave(ret){
      if(this.skip) return;
      const sz=this.sz; if(sz<8||sz>0x4000) return;
      const p=ptr(ret); if(p.isNull()) return;
      ring[ri%RING]={lo:p, hi:p.add(sz), sz:sz, fn:fn, cs:off(this.cs)}; ri++; nAlloc++;
    }
  });
  send({t:'info',msg:'hooked '+name+' @'+a});
}

function findChunk(P){
  const start=Math.max(0, ri-RING);
  for(let i=ri-1;i>=start;i--){ const c=ring[i%RING]; if(!c) continue;
    if(P.compare(c.lo)>=0 && P.compare(c.hi)<0) return {c:c, delta:P.sub(c.lo).toInt32()}; }
  return null;
}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString(), size:m.size});
  hookAlloc('malloc','m',0);
  hookAlloc('_Znwm','n',0);       // operator new(size_t)
  hookAlloc('calloc','c',1);      // calloc(n,size) → record size arg
  Interceptor.attach(base.add(OFF_DRIVER),{
    onEnter(args){
      if(hits>=MAXHIT) return;
      let len; try{ len=parseInt(this.context.x1.toString())&0xffffffff; }catch(e){ return; }
      if(len!==16) return;
      const P=this.context.x0;
      let val; try{ val=hx(P.readByteArray(16)); }catch(e){ return; }
      if(/^0+$/.test(val)) return;
      nDrv++;
      const f=findChunk(P);
      if(f){ hits++; send({t:'BIRTH', slot16:val, P:P.toString(), fn:f.c.fn, cs:f.c.cs, csz:f.c.sz, delta:f.delta}); }
      else { send({t:'NOCHUNK', slot16:val, P:P.toString()}); }
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,200); }; setTimeout(t,300); }
setInterval(function(){ send({t:'mon', nAlloc:nAlloc, nDrv:nDrv, hits:hits, ri:ri}); }, 3000);

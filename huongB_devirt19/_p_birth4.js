/*
 * _p_birth4.js — v3 + DEEP fp-chain walk to skip the tiny thunk 0x14fecc and
 * reach the REAL producer (thunk's caller).
 *
 * Frame layout at malloc onEnter (inside grow-helper 0x149d5c, before malloc prologue):
 *   context.fp == grow_x29 ; [grow_x29+8]=thunk_ret(0x14fed8) ; [grow_x29]=thunk_x29
 *   thunk 0x14fecc: stp x29,x30,[sp,#-0x10]!; mov x29,sp  => [thunk_x29+8]=producer_ret
 * So walk up to 6 frames and record each return addr as a libmetasec offset.
 */
'use strict';
const SO='libmetasec_ov.so';
const OFF_DRIVER=0x9fd98;
const OFF_GROW_RET=0x149e1c;
let base=null, lo=null, hi=null, GROWRET=null;
const RING=8192; const ring=new Array(RING); let ri=0;
let nAlloc=0, nGrow=0, nDrv=0, hits=0; const MAXHIT=16;

function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ return inSelf(p) ? '+0x'+p.sub(base).toString(16) : (p?p.toString():'?'); }catch(e){ return '?'; } }
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }

// walk fp-chain from a starting frame pointer, return array of {ret,fp} offsets
function walk(fp0, depth){
  const out=[]; let fp=fp0;
  for(let i=0;i<depth;i++){
    if(!fp || fp.isNull()) break;
    let ret, nfp;
    try{ ret=fp.add(8).readPointer(); nfp=fp.readPointer(); }catch(e){ break; }
    out.push(off(ret));
    fp=nfp;
  }
  return out;
}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size); GROWRET=base.add(OFF_GROW_RET);
  send({t:'info', base:base.toString()});

  const mallocp=Module.findGlobalExportByName('malloc');
  Interceptor.attach(mallocp,{
    onEnter(args){
      const ra=this.returnAddress;
      if(!inSelf(ra)){ this.skip=true; return; }
      this.skip=false; this.sz=parseInt(args[0].toString())|0; this.cs=ra;
      this.chain=null;
      if(ra.equals(GROWRET)){
        try{ this.chain=walk(this.context.fp, 6); }catch(e){ this.chain=['ERR']; }
      }
    },
    onLeave(ret){
      if(this.skip) return;
      const sz=this.sz; if(sz<8||sz>0x4000) return;
      const p=ptr(ret); if(p.isNull()) return;
      if(this.cs.equals(GROWRET)) nGrow++;
      ring[ri%RING]={lo:p, hi:p.add(sz), sz:sz, cs:off(this.cs), chain:this.chain}; ri++; nAlloc++;
    }
  });

  Interceptor.attach(base.add(OFF_DRIVER),{
    onEnter(args){
      if(hits>=MAXHIT) return;
      let len; try{ len=parseInt(this.context.x1.toString())&0xffffffff; }catch(e){ return; }
      if(len!==16) return;
      const P=this.context.x0;
      let val; try{ val=hx(P.readByteArray(16)); }catch(e){ return; }
      if(/^0+$/.test(val)) return;
      nDrv++;
      const start=Math.max(0, ri-RING); let f=null;
      for(let i=ri-1;i>=start;i--){ const c=ring[i%RING]; if(!c) continue;
        if(P.compare(c.lo)>=0 && P.compare(c.hi)<0){ f=c; break; } }
      if(f){ hits++; send({t:'BIRTH', slot16:val, P:P.toString(), cs:f.cs, csz:f.sz, chain:f.chain}); }
      else { send({t:'NOCHUNK', slot16:val, P:P.toString()}); }
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,200); }; setTimeout(t,300); }
setInterval(function(){ send({t:'mon', nAlloc:nAlloc, nGrow:nGrow, nDrv:nDrv, hits:hits}); }, 3000);

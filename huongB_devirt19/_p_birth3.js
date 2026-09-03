/*
 * _p_birth3.js — like v2 but for the P-birth callsite (+0x149e1c inside the
 * std::string/vector grow-helper @0x149d5c), ALSO frame-walk one level up to
 * capture the grow-helper's EXTERNAL caller (the container owner = producer-ish).
 *
 * At malloc onEnter, if returnAddress==base+0x149e1c we're inside grow-helper;
 * its own return addr (external caller) sits at [x29+8] because the helper did
 * `stp x29,x30,[sp,#0x40]; add x29,sp,#0x40`. malloc's Interceptor onEnter fires
 * before malloc's prologue, so context.fp still == grow-helper's x29.
 */
'use strict';
const SO='libmetasec_ov.so';
const OFF_DRIVER=0x9fd98;
const OFF_GROW_RET=0x149e1c;   // return addr after `bl malloc` in grow-helper
let base=null, lo=null, hi=null, GROWRET=null;
const RING=8192; const ring=new Array(RING); let ri=0;
let nAlloc=0, nGrow=0, nDrv=0, hits=0; const MAXHIT=16;

function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ return inSelf(p) ? '+0x'+p.sub(base).toString(16) : (p?p.toString():'?'); }
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }

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
      // if inside grow-helper, walk one frame up for the external caller
      this.ext='?';
      if(ra.equals(GROWRET)){
        try{ this.ext=off(this.context.fp.add(8).readPointer()); }catch(e){}
      }
    },
    onLeave(ret){
      if(this.skip) return;
      const sz=this.sz; if(sz<8||sz>0x4000) return;
      const p=ptr(ret); if(p.isNull()) return;
      if(this.cs.equals(GROWRET)) nGrow++;
      ring[ri%RING]={lo:p, hi:p.add(sz), sz:sz, cs:off(this.cs), ext:this.ext}; ri++; nAlloc++;
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
      if(f){ hits++; send({t:'BIRTH', slot16:val, P:P.toString(), cs:f.cs, csz:f.sz, ext:f.ext}); }
      else { send({t:'NOCHUNK', slot16:val, P:P.toString()}); }
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,200); }; setTimeout(t,300); }
setInterval(function(){ send({t:'mon', nAlloc:nAlloc, nGrow:nGrow, nDrv:nDrv, hits:hits}); }, 3000);

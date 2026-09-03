// _cand_dump.js — Dump I/O of the two per-cycle prep closures 0x10b940 & 0x10baa8 (producer candidates),
// plus the SM3-hash closure input via DRV. Offline we match each DRV slot16 V against candidate outputs to
// pin the producer. Rich deref (arg struct {len@4, ptr@8}; retval up to 2 levels) since output may be a
// std::string (bytes at *(ret)) not inline. Gate safe after 12s. Hooks = 3 fixed libmetasec entries (safe).
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac, C1=0x10b940, C2=0x10baa8;
let base=null, lo=null, hi=null, safe=false, seq=0, ndrv=0; const MAXD=6, MAXC=40;
let nc={};
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function cls(p){ try{ if(p.isNull()) return 'null'; }catch(e){ return 'bad'; }
  const s=selfOff(p); if(s) return s; try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p.toString(); }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function node(p, n){ // {ptr,cls,bytes, kids:[{off,ptr,cls,bytes}]}
  const o={ptr:p?p.toString():null, cls:p?cls(p):null, bytes:p?peek(p,n):null, kids:[]};
  if(p){ for(let i=0;i<6;i++){ try{ const q=p.add(i*8).readPointer(); if(q && !q.isNull()){ const b=peek(q,n); if(b) o.kids.push({off:i*8, ptr:q.toString(), cls:cls(q), bytes:b}); } }catch(e){ break; } } }
  return o;
}
function hookCand(off, name){
  Interceptor.attach(base.add(off), {
    onEnter(a){ if(!safe){this.skip=true;return;} nc[name]=(nc[name]||0)+1; if(nc[name]>MAXC){this.skip=true;return;}
      this.s=++seq; this.tid=this.threadId; this.x0=this.context.x0;
      this.argIn=node(this.context.x0,48); },
    onLeave(ret){ if(this.skip) return;
      send({t:'CAND', name:name, s:this.s, tid:this.tid, argIn:this.argIn,
            argOut:node(this.x0,48), ret:node(ret,48) }); }
  });
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  hookCand(C1,'c940'); hookCand(C2,'cbaa8');
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    send({t:'DRV', drv:ndrv, s:++seq, tid:this.threadId, V:V, P:c.x0.toString()}); }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 12000);
setInterval(function(){ send({t:'mon', safe:safe, seq:seq, ndrv:ndrv, nc:nc}); }, 3000);

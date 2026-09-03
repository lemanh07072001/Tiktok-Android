// _alloc_match.js — Catch slot16 P "at birth" by matching it to its allocator call.
// Arena is malloc-scattered (16B-aligned, size-class heap), NOT a bump region. So: hook the allocator
// family, log every in-arena return {ptr,size,ra}, then at the SM3 driver match the slot16 P to a logged
// allocation. The allocator's RETURN ADDRESS (ra) is an instruction INSIDE the producer function (malloc
// returns into the producer, which then fills P). => ra + size localize the producer's ARX directly.
// Window is derived at runtime from the first slot16 P (ASLR-safe): align P down to 256MB, +256MB.
// If NO alloc matches P (exact or containing) => P is not from libc malloc/new => custom slab => pivot to Stalker.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=40;
let win=null;                         // {lo:NativePointer, hi:NativePointer}
const RING=24000; const ringP=new Array(RING); const ringS=new Array(RING); const ringR=new Array(RING);
let ri=0, logged=0;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16); }catch(e){} return p?p.toString():'0'; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function record(ptr,sz,ra){
  if(!win||!ptr) return;
  try{ if(ptr.compare(win.lo)<0||ptr.compare(win.hi)>=0) return; }catch(e){ return; }
  // arena objects are 16B-aligned & small; keep small allocs to cut noise but allow up to 4KB for interior case
  if(!ptr.and(0xf).equals(0)) return;
  if(sz<=0 || sz>0x1000) return;
  ringP[ri]=ptr; ringS[ri]=sz; ringR[ri]=ra; ri=(ri+1)%RING; logged++;
}
function findAlloc(P){
  // newest-first: exact match, then containing
  let exact=null, contain=null;
  for(let k=0;k<RING;k++){
    const idx=(ri-1-k+RING)%RING; const p=ringP[idx]; if(!p) continue;
    if(p.equals(P)){ exact={p:p,sz:ringS[idx],ra:ringR[idx]}; break; }
    if(!contain){ try{ if(P.compare(p)>=0 && P.compare(p.add(ringS[idx]))<0) contain={p:p,sz:ringS[idx],ra:ringR[idx],delta:P.sub(p).toInt32()}; }catch(e){} }
  }
  return {exact:exact, contain:contain};
}
function hookAlloc(name, szArgIdx, retViaArg){
  const a=Module.findGlobalExportByName(name); if(!a) return false;
  try{
    Interceptor.attach(a, {
      onEnter(args){ this.sz = szArgIdx>=0 ? args[szArgIdx].toInt32() : 0;
                     if(name==='calloc') this.sz = args[0].toInt32()*args[1].toInt32();
                     if(retViaArg) this.memptr = args[0];
                     this.ra = this.returnAddress; },
      onLeave(retval){ if(!win) return;
        let ptr = retViaArg ? (this.memptr?this.memptr.readPointer():null) : retval;
        record(ptr, this.sz, this.ra); }
    });
    return true;
  }catch(e){ send({t:'hook_err', name:name, e:String(e)}); return false; }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  const hooked=[];
  [['malloc',0,false],['calloc',0,false],['realloc',1,false],['memalign',1,false],
   ['aligned_alloc',1,false],['posix_memalign',2,true],['_Znwm',0,false],['_Znam',0,false]]
   .forEach(function(h){ if(hookAlloc(h[0],h[1],h[2])) hooked.push(h[0]); });
  send({t:'hooked', names:hooked});
  Interceptor.attach(base.add(DRV), { onEnter(args){
    if(n>=MAX) return;
    const c=this.context; const x0=c.x0; let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){}
    if(w1!==16) return;
    let v0=x0?peek(x0,16):null;
    if(!v0 || v0==='00000000000000000000000000000000') return;
    n++;
    if(!win){                                        // learn arena window from first slot16 P (ASLR-safe)
      const w_lo=x0.and(ptr('0xFFFFFFFFF0000000'));  // align down 256MB
      win={lo:w_lo, hi:w_lo.add(ptr('0x10000000'))}; // +256MB
      send({t:'win', lo:win.lo.toString(), hi:win.hi.toString(), firstP:x0.toString()});
      return;                                        // this P's malloc predates logging; skip match
    }
    const f=findAlloc(x0);
    const rec={t:'MATCH', seq:n, P:x0.toString(), val:v0, logged:logged};
    if(f.exact){ rec.kind='exact'; rec.sz=f.exact.sz; rec.raRaw=f.exact.ra.toString(); rec.ra=modOff(f.exact.ra); rec.raSelf=off(f.exact.ra); }
    else if(f.contain){ rec.kind='contain'; rec.sz=f.contain.sz; rec.delta=f.contain.delta; rec.allocBase=f.contain.p.toString(); rec.raRaw=f.contain.ra.toString(); rec.ra=modOff(f.contain.ra); rec.raSelf=off(f.contain.ra); }
    else { rec.kind='NONE'; }
    send(rec);
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n, logged:logged, win:!!win}); }, 3000);

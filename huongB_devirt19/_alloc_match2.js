// _alloc_match2.js — Decisive classification of how slot16 P is born.
// v1 showed: P is NOT any malloc/new object (size<=4KB) even with zero eviction. Remaining escapes:
//  (A) P is interior to a LARGE (>4KB) malloc/new  -> widen size cap to 2MB.
//  (B) arena is a raw mmap slab, sub-allocated internally (no per-object allocator call) -> hook mmap/mmap64,
//      report which mmap region contains P + the mmap call-site RA (= who created the slab).
// Output per slot16 P: malloc match (exact/contain), mmap-region containing P (base,size,ra), and live range.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=12;
let win=null;
const RING=65536; const aP=new Array(RING); const aS=new Array(RING); const aR=new Array(RING); let ri=0, logged=0;
const mmaps=[];                       // {b:NativePointer, e:NativePointer, sz, ra}
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16); }catch(e){} return p?p.toString():'0'; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function inWin(p){ try{ return win && p.compare(win.lo)>=0 && p.compare(win.hi)<0; }catch(e){ return false; } }
function record(ptr,sz,ra){ if(!inWin(ptr)) return; if(sz<=0||sz>0x200000) return; aP[ri]=ptr; aS[ri]=sz; aR[ri]=ra; ri=(ri+1)%RING; logged++; }
function findAlloc(P){ let exact=null, contain=null;
  for(let k=0;k<RING;k++){ const idx=(ri-1-k+RING)%RING; const p=aP[idx]; if(!p) continue;
    if(p.equals(P)){ exact={sz:aS[idx],ra:aR[idx]}; break; }
    if(!contain){ try{ if(P.compare(p)>=0 && P.compare(p.add(aS[idx]))<0) contain={base:p,sz:aS[idx],ra:aR[idx],delta:P.sub(p).toInt32()}; }catch(e){} } }
  return {exact:exact, contain:contain}; }
function findMmap(P){ for(let i=mmaps.length-1;i>=0;i--){ const m=mmaps[i]; try{ if(P.compare(m.b)>=0 && P.compare(m.e)<0) return m; }catch(e){} } return null; }
function hookAlloc(name, szArgIdx, retViaArg){ const a=Module.findGlobalExportByName(name); if(!a) return false;
  try{ Interceptor.attach(a, {
    onEnter(args){ this.sz = szArgIdx>=0 ? args[szArgIdx].toInt32() : 0;
      if(name==='calloc') this.sz=args[0].toInt32()*args[1].toInt32(); if(retViaArg) this.memptr=args[0]; this.ra=this.returnAddress; },
    onLeave(retval){ if(!win) return; let ptr=retViaArg?(this.memptr?this.memptr.readPointer():null):retval; record(ptr,this.sz,this.ra); } });
    return true; }catch(e){ send({t:'hook_err',name:name,e:String(e)}); return false; } }
function hookMmap(name){ const a=Module.findGlobalExportByName(name); if(!a) return false;
  try{ Interceptor.attach(a, { onEnter(args){ this.len=args[1].toInt32(); this.ra=this.returnAddress; },
    onLeave(retval){ if(!retval || retval.equals(ptr(-1))) return; if(!inWin(retval)) return;
      mmaps.push({b:retval, e:retval.add(this.len), sz:this.len, ra:this.ra});
      send({t:'mmap', base:retval.toString(), sz:'0x'+this.len.toString(16), ra:modOff(this.ra)}); } });
    return true; }catch(e){ send({t:'hook_err',name:name,e:String(e)}); return false; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  const hooked=[]; [['malloc',0,false],['calloc',0,false],['realloc',1,false],['memalign',1,false],['aligned_alloc',1,false],['posix_memalign',2,true],['_Znwm',0,false]]
    .forEach(function(h){ if(hookAlloc(h[0],h[1],h[2])) hooked.push(h[0]); });
  ['mmap','mmap64'].forEach(hookMmap); send({t:'hooked', names:hooked});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(n>=MAX) return; const c=this.context; const x0=c.x0;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    let v0=x0?peek(x0,16):null; if(!v0||v0==='00000000000000000000000000000000') return; n++;
    if(!win){ const w_lo=x0.and(ptr('0xFFFFFFFFF0000000')); win={lo:w_lo, hi:w_lo.add(ptr('0x10000000'))};
      send({t:'win', lo:win.lo.toString(), hi:win.hi.toString(), firstP:x0.toString()}); return; }
    const f=findAlloc(x0); const mm=findMmap(x0);
    let rng=null; try{ const r=Process.findRangeByAddress(x0); if(r) rng={b:r.base.toString(),sz:'0x'+r.size.toString(16),prot:r.protection,file:r.file?r.file.path:null}; }catch(e){}
    const rec={t:'MATCH', seq:n, P:x0.toString(), val:v0, logged:logged};
    if(f.exact){ rec.malloc='exact'; rec.sz=f.exact.sz; rec.ra=modOff(f.exact.ra); rec.raSelf=off(f.exact.ra); }
    else if(f.contain){ rec.malloc='contain'; rec.sz=f.contain.sz; rec.delta=f.contain.delta; rec.allocBase=f.contain.base.toString(); rec.ra=modOff(f.contain.ra); rec.raSelf=off(f.contain.ra); }
    else rec.malloc='NONE';
    if(mm){ rec.mmapBase=mm.b.toString(); rec.mmapSz='0x'+mm.sz.toString(16); rec.mmapRa=modOff(mm.ra); rec.mmapDelta=x0.sub(mm.b).toInt32(); } else rec.mmap='NONE';
    rec.rng=rng; send(rec); }});
  send({t:'ready'}); return true; }
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n, logged:logged, mmaps:mmaps.length, win:!!win}); }, 3000);

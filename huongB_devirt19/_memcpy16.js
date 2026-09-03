// _memcpy16.js — Test whether slot16 P is filled via a 16-byte memcpy/memmove, and if so grab the producer.
// Region-trap failed: the slab is app-wide shared, so write frequency is dominated by unrelated copies.
// Narrow by CONTENT, not frequency: hook memcpy/memmove/__memcpy_chk, keep only len==16 copies whose dst is
// in the arena window; index by dst. At the SM3 driver, match the slot16 P: (1) exact dst==P copy, else
// (2) a copy whose src-bytes == the slot16 value. That copy's returnAddress = the PRODUCER call-site, and its
// src = the buffer the ARX just wrote. If NO copy matches => producer stores inline (stp) => pivot to unwind/Stalker.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=40;
let win=null;
const RING=40000; const dArr=new Array(RING); const sArr=new Array(RING); const vArr=new Array(RING); const rArr=new Array(RING); let ri=0, logged=0;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function modOff(p){ try{ const m=Process.findModuleByAddress(p); if(m) return m.name+'+0x'+p.sub(m.base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function inWin(p){ try{ return win && p.compare(win.lo)>=0 && p.compare(win.hi)<0; }catch(e){ return false; } }
function logCopy(dst,src,ra){ if(!inWin(dst)) return; const v=peek(src,16); if(!v) return;
  dArr[ri]=dst; sArr[ri]=src; vArr[ri]=v; rArr[ri]=ra; ri=(ri+1)%RING; logged++; }
function findByDst(P){ for(let k=0;k<RING;k++){ const i=(ri-1-k+RING)%RING; const d=dArr[i]; if(!d) continue; if(d.equals(P)) return {src:sArr[i],val:vArr[i],ra:rArr[i]}; } return null; }
function findByVal(val){ for(let k=0;k<RING;k++){ const i=(ri-1-k+RING)%RING; if(!dArr[i]) continue; if(vArr[i]===val) return {dst:dArr[i],src:sArr[i],ra:rArr[i]}; } return null; }
function hookCpy(name, dstI, srcI, lenI){ const a=Module.findGlobalExportByName(name); if(!a) return false;
  try{ Interceptor.attach(a, { onEnter(args){ this.len=args[lenI].toInt32();
      if(this.len!==16){ this.skip=true; return; } this.dst=args[dstI]; this.src=args[srcI]; this.ra=this.returnAddress; },
    onLeave(r){ if(this.skip||!win) return; logCopy(this.dst, this.src, this.ra); } });
    return true; }catch(e){ send({t:'hook_err',name:name,e:String(e)}); return false; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  const hooked=[]; [['memcpy',0,1,2],['memmove',0,1,2],['__memcpy_chk',0,1,2],['__memmove_chk',0,1,2]]
    .forEach(function(h){ if(hookCpy(h[0],h[1],h[2],h[3])) hooked.push(h[0]); });
  send({t:'hooked', names:hooked});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(n>=MAX) return; const c=this.context; const x0=c.x0;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    let v0=peek(x0,16); if(!v0||v0==='00000000000000000000000000000000') return; n++;
    if(!win){ const w=x0.and(ptr('0xFFFFFFFFF0000000')); win={lo:w, hi:w.add(ptr('0x10000000'))};
      send({t:'win', lo:win.lo.toString(), hi:win.hi.toString(), firstP:x0.toString()}); return; }
    const byDst=findByDst(x0); const byVal=byDst?null:findByVal(v0);
    const rec={t:'MATCH', seq:n, P:x0.toString(), val:v0, logged:logged};
    if(byDst){ rec.kind='dst=='; rec.ra=modOff(byDst.ra); rec.raSelf=off(byDst.ra); rec.src=byDst.src.toString(); rec.srcVal=byDst.val; }
    else if(byVal){ rec.kind='val=='; rec.ra=modOff(byVal.ra); rec.raSelf=off(byVal.ra); rec.dst=byVal.dst.toString(); rec.src=byVal.src.toString(); }
    else rec.kind='NONE';
    send(rec); }});
  send({t:'ready'}); return true; }
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n, logged:logged, win:!!win}); }, 3000);

// _mam_producer6.js — producer localizer: SURVIVABLE hook + crash-free MAM.
// WHY the hook site changed: producer3 hooked base+0xa0430 (a mid-function `mov x1,x19`). Frida must
// relocate that lone instruction -> fragile -> triggered the frida-agent PAC/TLS SIGSEGV on ChromiumNet0.
// _slot16_read.js hooks the memcpy ENTRY at 0x172a50 (clean prologue relocation) and SURVIVED 2/2.
// So: reuse that proven entry hook to LEARN the pool address (args[1]=src on the a0440 read bucket),
// then arm MAM (mprotect-based, no code patching -> no PAC crash) forward over the pool page(s).
// MODEL: producer STRs 16B slot16 DIRECTLY into a fresh sequential-pool buffer BEFORE the a0440 memcpy
// copies it out. We learn buffer P from request N's memcpy; the page is now touched, so MAM's next-access
// trap on that page == request N+1's producer STR -> details.from = producer PC (META:offset).
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50;          // proven-survivable entry hook (same as _slot16_read.js)
const READBUCKET=0xa0440;       // returnAddress offset that == the slot16 arena->consumer copy
const BACK=0x2000, SPAN=0x200000; // arm [pageOf(src)-BACK, +2MB) forward per distinct pool page
const KNOWN=new Set(['46c03b52742b3f2615a3abdf1636b754','443dfca2529e547fe73a8e0aa4bd2c82',
  '4c6b995344026d0cac8df6620a3a96ca','58f2de715ba986da8d78155894b9a7aa','d951198a57936f91a3d14cecd63cbb6a']);
let base=null, lo=null, hi=null, nRd=0, nWr=0, reported=0, hits=[];
const armedPages=new Set(); const srcSeen=[];
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function cls(pc){ if(!pc) return 'null';
  if(pc.compare(lo)>=0&&pc.compare(hi)<0) return 'META:'+pc.sub(base).toString(16);
  const m=Process.findModuleByAddress(pc); if(m) return m.name+':'+pc.sub(m.base).toString(16);
  return 'anon:'+pc.toString(); }
function onAcc(d){
  if(d.operation!=='write') return;
  nWr++;
  let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
  const e=ent(val), pcCls=cls(d.from), isMeta=pcCls.indexOf('META:')===0, known=val&&KNOWN.has(val);
  if(known || (isMeta && e>=10)){
    const rec={pc:pcCls, addr:d.address.toString(), val:val, e:e, known:known};
    hits.push(rec);
    if(reported<80){ reported++; send({t:'HIT', pc:pcCls, addr:rec.addr, val:val, e:e, known:known}); }
  }
}
function armAround(src){
  const start=pageOf(src).sub(BACK); const key=start.toString();
  if(armedPages.has(key)) return; armedPages.add(key);
  // re-enable takes the full set of ranges each call; rebuild from all armed windows
  const ranges=[...armedPages].map(k=>({base:ptr(k), size:SPAN}));
  try{ MemoryAccessMonitor.enable(ranges, {onAccess:onAcc});
       send({t:'armed', windows:ranges.length, newStart:start.toString(), src:src.toString()}); }
  catch(e){ send({t:'err', msg:'MAM.enable '+e}); armedPages.delete(key); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); }
  Interceptor.attach(base.add(MEMCPY),{onEnter(args){
    let sz; try{ sz=args[2].toInt32(); }catch(e){ return; } if(sz!==16) return;
    let ra; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0) return;
    if(ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;   // only the slot16 read bucket
    let src,V; try{ src=args[1]; V=hx(src.readByteArray(16)); }catch(e){ return; }
    if(ent(V)<10 && !KNOWN.has(V)) return;      // require binary slot16 (skip zero/ascii)
    nRd++;
    if(srcSeen.length<24){ srcSeen.push(src.toString()); }
    armAround(src);
    if(nRd<=40) send({t:'rd', ord:nRd, src:src.toString(), val:V, band:src.shr(32).toString(16)});
  }});
  send({t:'info',msg:'mam-producer6 installed base='+base+' memcpy='+base.add(MEMCPY)});
  setInterval(function(){ send({t:'mon', nRd:nRd, nWr:nWr, hits:hits.length, armed:armedPages.size}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

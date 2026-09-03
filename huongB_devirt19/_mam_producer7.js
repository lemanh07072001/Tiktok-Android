// _mam_producer7.js — SINGLE-ENABLE MAM, tiny footprint, delayed arm.
// producer6 crashed with SEGV_ACCERR (protection failure) in libcrypto ASN1/X509 on TTNet-Fg-W:
//   (a) I called MemoryAccessMonitor.enable() 5x (re-arm) -> orphaned PROT_NONE pages (MAM handler
//       didn't cover them) -> escaped fault. MAM must be enabled EXACTLY ONCE.
//   (b) the pool arena (band 0x77) is SHARED with BoringSSL cert parsing -> a 2MB window = fault storm.
// FIX: (1) hook memcpy(0x172a50) [proven-survivable] to LEARN the exact pool pages (src=args[1]).
//      (2) collect distinct pool PAGES for COLLECT_MS while the TLS cert-validation storm runs.
//      (3) ONE enable() over just those 4KB pages (tiny footprint) AFTER the storm settles.
//      (4) onAccess: robust, report writes w/ libmetasec PC + entropy; DISABLE on first producer hit.
// Rationale: scudo reuses freed pool buffers; a later heartbeat/register producer STR reuses one of the
// armed pages -> first-access trap == the producer PC (META:offset). Tiny idle pages minimize BoringSSL noise.
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const COLLECT_MS=22000;          // learn pool pages during startup; arm after the cert storm settles
const MAXPAGES=12;               // cap armed footprint (<= 48KB)
const KNOWN=new Set(['46c03b52742b3f2615a3abdf1636b754','443dfca2529e547fe73a8e0aa4bd2c82',
  '4c6b995344026d0cac8df6620a3a96ca','58f2de715ba986da8d78155894b9a7aa','d951198a57936f91a3d14cecd63cbb6a']);
let base=null, lo=null, hi=null, nRd=0, nWr=0, reported=0, armed=false, disabled=false;
const pages=new Map();           // pageStr -> {hits, lastVal}
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function cls(pc){ if(!pc) return 'null';
  if(pc.compare(lo)>=0&&pc.compare(hi)<0) return 'META:'+pc.sub(base).toString(16);
  const m=Process.findModuleByAddress(pc); if(m) return m.name+':'+pc.sub(m.base).toString(16);
  return 'anon:'+pc.toString(); }
function onAcc(d){
  nWr++; // count every trapped access
  if(d.operation!=='write') return;
  let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
  const e=ent(val), pcCls=cls(d.from), isMeta=pcCls.indexOf('META:')===0, known=val&&KNOWN.has(val);
  if(known || (isMeta && e>=10)){
    if(reported<80){ reported++; send({t:'HIT', pc:pcCls, addr:d.address.toString(), val:val, e:e, known:known, op:d.operation}); }
    if(isMeta && !disabled){ disabled=true; try{ MemoryAccessMonitor.disable(); }catch(_){} send({t:'DISABLED_after_producer', pc:pcCls}); }
  } else if(reported<80 && isMeta){
    // libmetasec write but low-entropy: still interesting, log lightly
    reported++; send({t:'metaW', pc:pcCls, addr:d.address.toString(), val:val, e:e });
  }
}
function armOnce(){
  if(armed) return; armed=true;
  const ranges=[...pages.keys()].slice(0,MAXPAGES).map(k=>({base:ptr(k), size:0x1000}));
  if(!ranges.length){ send({t:'err',msg:'no pool pages collected'}); return; }
  try{ MemoryAccessMonitor.enable(ranges, {onAccess:onAcc});
       send({t:'armed_once', pages:ranges.length, list:ranges.map(r=>r.base.toString())}); }
  catch(e){ send({t:'err', msg:'MAM.enable '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); }
  Interceptor.attach(base.add(MEMCPY),{onEnter(args){
    let sz; try{ sz=args[2].toInt32(); }catch(e){ return; } if(sz!==16) return;
    let ra; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0) return;
    if(ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let src,V; try{ src=args[1]; V=hx(src.readByteArray(16)); }catch(e){ return; }
    if(ent(V)<10 && !KNOWN.has(V)) return;
    nRd++;
    const pk=pageOf(src).toString();
    if(!pages.has(pk)) pages.set(pk,{hits:0,lastVal:V});
    pages.get(pk).hits++; pages.get(pk).lastVal=V;
    if(nRd<=40) send({t:'rd', ord:nRd, src:src.toString(), val:V, page:pk, known:KNOWN.has(V)});
  }});
  send({t:'info',msg:'mam-producer7 installed base='+base});
  setTimeout(armOnce, COLLECT_MS);   // single delayed enable, after cert storm
  setInterval(function(){ send({t:'mon', nRd:nRd, nWr:nWr, pages:pages.size, armed:armed, disabled:disabled}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

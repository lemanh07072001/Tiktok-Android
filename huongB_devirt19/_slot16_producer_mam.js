// _slot16_producer_mam.js — Route B step 1: catch the NATIVE write(s) to slot16's stable home.
// Lever: signing path deterministic; slot16 lands at a stable native home each heartbeat (rewritten
// with a NEW value each time). Arm MAM (mprotect SW-watchpoint, works on Exynos no-HW-wp) on that
// page; record write PCs across subsequent heartbeats. Producer store = the write PC that is NOT a
// generic memcpy/memmove copier.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function modoff(a){
  try{const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){}
  try{const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection;}catch(e){}
  return '?';
}
let base=null;
const chain={};
let homes=[];           // exact native addresses currently holding slot16
let pages=[];           // NativePointer page bases to watch
let armed=false;
const writes=[]; const reads=[]; let hb=0;
const PAGE=0x1000;
function pageOf(a){ return a.and(ptr(PAGE-1).not()); }
function scanNativeHomes(hexval){
  const pat=hexval.replace(/(..)/g,'$1 ').trim(); const out=[];
  for(const r of Process.enumerateRanges('rw-')){
    if(r.base.compare(ptr('0x7000000000'))<0) continue;   // native heap/stack only (skip low dalvik)
    let hits; try{hits=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
    for(const h of hits) out.push(h.address);
    if(out.length>40) break;
  }
  return out;
}
function rearm(){ try{ MemoryAccessMonitor.enable(pages.map(p=>({base:p,size:PAGE})),{onAccess:onAcc}); armed=true; }catch(e){ send({t:'err',msg:'rearm '+e}); } }
function nearHome(addr){
  for(const h of homes){ const d=addr.sub(h).toInt32(); if(d>=-16 && d<48) return {home:h.toString(),delta:d}; }
  return null;
}
function onAcc(d){
  const nh=nearHome(d.address);
  if(nh){
    const rec={op:d.operation, from:modoff(d.from), fromRaw:d.from.toString(), addr:d.address.toString(), home:nh.home, delta:nh.delta};
    if(d.operation==='write'){ writes.push(rec); if(writes.length<=40) send({t:'W',rec:rec}); }
    else { reads.push(rec); }
  }
  rearm();  // keep watching
  if(writes.length>=40){ try{MemoryAccessMonitor.disable();}catch(e){} send({t:'done',writes:writes,reads:reads.slice(0,20)}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot='',pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    delete chain[tid];
    if(slot==='00'.repeat(16)||pr>=12) return;
    hb++;
    if(!armed){
      homes=scanNativeHomes(slot);
      if(homes.length===0){ send({t:'info',msg:'hb'+hb+' slot='+slot+' no native home yet'}); return; }
      const ps={}; homes.forEach(h=>{ps[pageOf(h).toString()]=pageOf(h);});
      pages=Object.keys(ps).map(k=>ps[k]);
      send({t:'arm', hb:hb, slot16:slot, nhomes:homes.length, homes:homes.slice(0,8).map(x=>x.toString()), pages:pages.map(x=>x.toString())});
      rearm();
    } else {
      send({t:'hb', hb:hb, slot16:slot, writes_so_far:writes.length});
    }
  }});
  send({t:'info',msg:'producer-mam installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

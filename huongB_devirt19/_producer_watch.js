// _producer_watch.js — SW write-watch (MemoryAccessMonitor) to catch the PRODUCER store.
// 1) hook internal memcpy 0x172a50; first copy whose src is a header entry (tag 020102 at src-10)
//    => learn the arena region R + entry addr; arm a BOUNDED write-monitor window around it.
// 2) MemoryAccessMonitor.onAccess: for WRITES landing where a high-entropy 16B value sits, record
//    details.from (the writing instruction PC) + region => that's the producer store. Re-enable.
// Pool is produced incrementally (@4-6s) so writes AFTER arming get caught.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
const WIN=0x60000; // 384KB window around first entry
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){}
  return 'anon?';
}
function hentropy(u){ let zero=0,asc=0,set={}; for(let i=0;i<16;i++){ if(u[i]===0)zero++; if(u[i]>=0x20&&u[i]<=0x7e)asc++; set[u[i]]=1; } return zero<=4&&asc<12&&Object.keys(set).length>=10; }
let armed=false; const seenPC={}; let nprod=0; let winBase=null, winSize=0;
let mod=null, mlo=null, mhi=null;
function arm(base,size){
  try{
    MemoryAccessMonitor.enable({base:base, size:size}, {onAccess(d){
      try{
        if(d.operation!=='write'){ return; }
        const addr=d.address;
        let u; try{ u=new Uint8Array(ptr(addr).readByteArray(16)); }catch(e){ u=null; }
        const from=d.from;
        const inMod = from && from.compare(mlo)>=0 && from.compare(mhi)<0;
        if(u && hentropy(u) && inMod){
          const pc=from.toString();
          if(!seenPC[pc] && nprod<20){ seenPC[pc]=1; nprod++;
            send({t:'prod', from:pc, from_region:region(from), addr:addr.toString(), val16:hx(addr,16), pre10:hx(ptr(addr).sub(10),10)});
          }
        }
      }catch(e){}
      finally{ try{ MemoryAccessMonitor.enable({base:winBase,size:winSize},{onAccess:arguments.callee}); }catch(e){} }
    }});
  }catch(e){ send({t:'err',msg:'arm-fail:'+e}); }
}
function install(){
  mod=Process.findModuleByName(SO); if(!mod) return false;
  const base=mod.base; mlo=base; mhi=base.add(mod.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(armed) return;
    const len=a[2].toInt32(); if(len<16||len>32) return;
    const src=a[1];
    let pre; try{ pre=hx(src.sub(16),16); }catch(e){ return; }
    if(!pre || pre.slice(0,12)!=='020102000000') return; // src is a header entry value (tag @src-16)
    const r=Process.findRangeByAddress(src); if(!r) return;
    armed=true;
    let lo=src.sub(WIN/2); if(lo.compare(r.base)<0) lo=r.base;
    let hiEnd=r.base.add(r.size);
    let sz=WIN; if(lo.add(sz).compare(hiEnd)>0) sz=hiEnd.sub(lo).toInt32();
    winBase=lo; winSize=sz;
    send({t:'armed', entry:src.toString(), region_base:r.base.toString(), region_size:r.size, win_base:winBase.toString(), win_size:winSize});
    arm(winBase, winSize);
  }});
  send({t:'info',msg:'producer-watch installed (arm on first header entry)'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

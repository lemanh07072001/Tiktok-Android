// _mam_producer2.js — broad-region MAM diagnostic to catch the slot16 producer's FIRST write per page.
// On the first a0440 read we learn the pool location (0x7d0c...). Arm ONE broad MAM region spanning the
// pool's forward growth. one-shot-per-page => the FIRST access to each fresh buffer page traps; since the
// producer STRs into a freshly-allocated page before anyone reads it, that first-write trap = producer.
// Log EVERY write with pc (classified libmetasec / arena-0x7e / other), value & entropy. Correlate each
// a0440 read(A,V) with the write whose addr is in page(A).
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50, READOFF='a0440';
const BACK=0x8000, SPAN=0x300000;   // arm [firstSrcPage-BACK, +SPAN) ~3MB forward
let base=null, lo=null, hi=null, ord=0, armed=false, writes=[], nWr=0, reported=0;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; } // #nonprintable bytes
function cls(pc){ if(pc.compare(lo)>=0&&pc.compare(hi)<0) return 'meta:'+pc.sub(base).toString(16);
                 const s=pc.toString(); if(s.indexOf('0x7e')===0||s.indexOf('0x7f')===0) return 'arena:'+s; return 'oth:'+s; }
function arm(firstSrc){
  const start=pageOf(firstSrc).sub(BACK);
  try{
    MemoryAccessMonitor.enable([{base:start, size:SPAN}], { onAccess(d){
      if(d.operation!=='write') return;
      nWr++;
      let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
      const rec={ord:ord, pc:cls(d.from), addr:d.address.toString(), val:val, e:ent(val)};
      writes.push(rec); if(writes.length>16384) writes.shift();
      // live: high-entropy writes (potential slot16) or any libmetasec-pc write
      if((rec.e>=10 || rec.pc.indexOf('meta:')===0) && reported<40){ reported++;
        send({t:'wr', pc:rec.pc, addr:rec.addr, val:val, e:rec.e, ord:ord}); }
    }});
    armed=true; send({t:'armed', start:start.toString(), span:'0x'+SPAN.toString(16)});
  }catch(e){ send({t:'err', msg:'MAM.enable '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); }
  Interceptor.attach(base.add(MEMCPY),{onEnter(args){
    const sz=args[2].toInt32(); if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!==READOFF) return;
    let A,V; try{ A=args[1]; V=hx(args[1].readByteArray(16)); }catch(e){ return; }
    if(ent(V)<10) return; // require high-entropy binary slot16
    ord++;
    if(!armed) arm(A);
    const pa=pageOf(A).toString();
    const hit=writes.filter(w=>pageOf(ptr(w.addr)).toString()===pa);
    send({t:'rd', ord:ord, src:A.toString(), val:V,
          producer: hit.length? hit.map(h=>({pc:h.pc, addr:h.addr, val:h.val, e:h.e})).slice(0,6):null});
  }});
  send({t:'info',msg:'mam-producer2 installed base='+base});
  setInterval(function(){ send({t:'mon', ord:ord, nWr:nWr, armed:armed}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

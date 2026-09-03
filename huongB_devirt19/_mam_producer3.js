// _mam_producer3.js — producer localizer, CRASH-SAFE read trigger.
// producer2 hooked GLOBAL memcpy -> frida-agent SIGSEGV on ChromiumNet0 (PAC race under the
// startup memcpy storm from Chromium net threads). Fix: hook the slot16-SPECIFIC call site inside
// libmetasec instead: base+0xa0430 = `mov x1, x19` where x19 = producer buffer (src of the 16B read).
// That instruction runs ONLY on the slot16 read path, on one thread, a handful of times per burst ->
// no Chromium threads, no high-frequency trampoline -> avoids the PAC crash entirely.
// On the first slot16 read we learn the pool page and arm ONE broad MAM region forward. MAM is
// mprotect-based (no code patching) -> the producer's STR into a fresh pool page traps => producer PC.
// The producer's stored VALUE is the slot16 itself, so a high-entropy write == direct producer hit.
'use strict';
const SO='libmetasec_ov.so';
const READSITE=0xa0430;              // mov x1,x19 ; x19 = src (producer buffer)
const BACK=0x8000, SPAN=0x300000;    // arm [firstSrcPage-BACK, +SPAN) ~3MB forward
let base=null, lo=null, hi=null, ord=0, armed=false, writes=[], nWr=0, reported=0, nRd=0;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
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
      // live: the producer STRs the slot16 itself -> a high-entropy write IS the producer, or any libmetasec-pc write
      if((rec.e>=10 || rec.pc.indexOf('meta:')===0) && reported<60){ reported++;
        send({t:'wr', pc:rec.pc, addr:rec.addr, val:val, e:rec.e, ord:ord}); }
    }});
    armed=true; send({t:'armed', start:start.toString(), span:'0x'+SPAN.toString(16), firstSrc:firstSrc.toString()});
  }catch(e){ send({t:'err', msg:'MAM.enable '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); }
  // hook the slot16 read call-site (mov x1,x19). onEnter: x19 = src producer buffer.
  Interceptor.attach(base.add(READSITE),{onEnter(){
    let src,V; try{ src=this.context.x19; V=hx(src.readByteArray(16)); }catch(e){ return; }
    if(ent(V)<10) return;             // require high-entropy binary slot16
    nRd++; ord++;
    if(!armed) arm(src);
    const pa=pageOf(src).toString();
    const hit=writes.filter(w=>pageOf(ptr(w.addr)).toString()===pa);
    send({t:'rd', ord:ord, src:src.toString(), val:V,
          producer: hit.length? hit.map(h=>({pc:h.pc, addr:h.addr, val:h.val, e:h.e})).slice(0,6):null});
  }});
  send({t:'info',msg:'mam-producer3 installed base='+base+' readsite='+base.add(READSITE)});
  setInterval(function(){ send({t:'mon', ord:ord, nRd:nRd, nWr:nWr, armed:armed}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

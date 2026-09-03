// _mam_producer.js — find the slot16 PRODUCER store via MemoryAccessMonitor (software, mprotect-based;
// no code instrumentation -> stealthier than Stalker, which crashed this hardened app).
// Model: a0440 memcpy reads slot16 from a FRESH sequential-pool buffer (x19, region 0x7d0c...).
// The producer STR'd it there first. On each a0440 read from src A_n, arm MAM on a forward window
// [A_n+PAGE, A_n+WIN). The next request's producer writes into a fresh page there -> FIRST access to that
// fresh page traps -> details.from = producer PC. Correlate: a later a0440 read from P confirms the write
// that filled page(P) was the producer.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50, READOFF='a0440';
const PAGE=0x1000, WIN=0x10000;   // watch 16 pages ahead of the current buffer
let base=null, lo=null, hi=null, ord=0, reads=[], writes=[], armedFrom=null, reported=0;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function isBin(v){ if(v==='00'.repeat(16))return false; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return pr<12; }

function armWindow(srcPtr){
  const start=pageOf(srcPtr).add(PAGE);
  try{
    MemoryAccessMonitor.enable([{base:start, size:WIN}], { onAccess(d){
      // d.operation: 'read'|'write'|'execute'; d.from: pc; d.address: accessed addr
      if(d.operation!=='write') return;
      let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
      const rec={ord:ord, op:d.operation, pc:d.from.compare(lo)>=0&&d.from.compare(hi)<0 ? d.from.sub(base).toString(16):('EXT:'+d.from),
                  addr:d.address.toString(), val:val };
      writes.push(rec); if(writes.length>4096) writes.shift();
      // live signal: a write whose value already looks like binary slot16
      if(val && isBin(val) && reported<20){ reported++;
        send({t:'wr', pc:rec.pc, addr:rec.addr, val:val, ord:ord}); }
    }});
    armedFrom=start;
  }catch(e){ send({t:'err', msg:'MAM.enable '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor in this frida'}); }
  Interceptor.attach(base.add(MEMCPY),{onEnter(args){
    const sz=args[2].toInt32(); if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){ return; }
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!==READOFF) return;
    let A,V; try{ A=args[1]; V=hx(args[1].readByteArray(16)); }catch(e){ return; }
    if(!isBin(V)) return;
    ord++;
    const P=A.toString();
    // correlate: did a recorded write fill page(A) ?
    const pa=pageOf(A).toString();
    const hit=writes.filter(w=>pageOf(ptr(w.addr)).toString()===pa);
    reads.push({ord:ord, src:P, val:V});
    send({t:'rd', ord:ord, src:P, val:V, nWriteHitsInPage:hit.length,
          producer: hit.length? hit.map(h=>({pc:h.pc, addr:h.addr, val:h.val})).slice(0,4):null });
    // slide the window ahead of this buffer for the NEXT request
    armWindow(A);
  }});
  send({t:'info',msg:'mam-producer installed base='+base});
  setInterval(function(){ send({t:'mon', ord:ord, nReads:reads.length, nWrites:writes.length, armedFrom:armedFrom?armedFrom.toString():null}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

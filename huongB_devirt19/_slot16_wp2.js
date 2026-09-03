// _slot16_wp2.js — catch the slot16 PRODUCER store via a MASKED hardware write-watchpoint over the pool band.
// Learned: (1) app fires access-violation SIGSEGVs constantly (ART null-checks) -> handler MUST return false
//   for those. (2) HW watchpoint traps arrive as type 'breakpoint'. (3) native stores route to the handler.
// Plan: reader (0x172a50, ret==0xa0440, sz==16) reveals pool addr P. After a few, compute a power-of-2 band
//   covering them and arm ONE masked write-WP on the signing thread. The producer (inside VM 0x55950) writing
//   the next slot16 into the band traps -> handler gives context.pc = PRODUCER STORE PC (pc inSelf).
// On hit: record, unset WP (avoid re-trap loop), re-arm on the next reader. Collect several; the recurring
//   pc-inSelf store = the producer. Falls back to exact-P (size 8, up to 4 slots) if masked arm is rejected.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
const GRAN=0x20000;                    // masked band size (power of 2)
let base=null, lo=null, hi=null, done=false;
let nRd=0, nBP=0, armedMode=null, bandBase=null, sigTid=null, needArm=true;
const Ps=[];                           // distinct pool addrs seen (fresh)
const recentP=[];                      // for exact-P fallback (max 4)
const hits=[];
function selfOff(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function threadFor(tid){ try{ return Process.enumerateThreads().find(function(t){return t.id===tid;})||null; }catch(e){ return null; } }
function unarmAll(){
  try{ Process.enumerateThreads().forEach(function(t){ for(let i=0;i<4;i++){ try{t.unsetHardwareWatchpoint(i);}catch(e){} } }); }catch(e){}
}
function bandFor(addr){ // align down to GRAN
  const a=uint64(addr.toString());
  const mask=uint64(GRAN-1);
  return ptr('0x'+a.and(mask.not()).toString(16));
}
function armMasked(){
  const t=threadFor(sigTid); if(!t){ send({t:'arm_miss'}); return false; }
  try{ t.setHardwareWatchpoint(0, bandBase, GRAN, 'w'); armedMode='masked';
       send({t:'armed_masked', band:bandBase.toString(), size:GRAN, tid:sigTid}); return true; }
  catch(e){ send({t:'masked_rejected', e:String(e)}); return false; }
}
function armExact(){
  const t=threadFor(sigTid); if(!t){ send({t:'arm_miss'}); return false; }
  let armed=[];
  for(let i=0;i<recentP.length && i<4;i++){
    try{ t.setHardwareWatchpoint(i, recentP[i], 8, 'w'); armed.push(recentP[i].toString()); }catch(e){ send({t:'arm_err', slot:i, e:String(e)}); }
  }
  armedMode='exact'; send({t:'armed_exact', slots:armed, tid:sigTid}); return armed.length>0;
}
function doArm(){
  if(!sigTid) return;
  if(bandBase){ if(armMasked()) { needArm=false; return; } }
  if(armExact()) needArm=false;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  Process.setExceptionHandler(function(d){
    if(d.type==='access-violation') return false;         // app null-checks: pass through
    if(d.type!=='breakpoint' && d.type!=='single-step') return false;
    try{
      const pc=d.context.pc; let mem=null,op=null;
      try{ if(d.memory){ mem=d.memory.address?d.memory.address.toString():null; op=d.memory.operation; } }catch(e){}
      nBP++;
      const rec={n:nBP, pc:selfOff(pc), pcRaw:pc.toString(), inSelf:inSelf(pc), mem:mem, op:op, tid:Process.getCurrentThreadId()};
      hits.push(rec); send({t:'BP', rec:rec});
      unarmAll(); needArm=true;                            // stop re-trap; re-arm on next reader
      if(hits.filter(function(h){return h.inSelf;}).length>=6){ done=true; send({t:'stopped', hits:hits}); }
      return true;
    }catch(e){ send({t:'bp_err', e:String(e)}); unarmAll(); return true; }
  });
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done)return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){return;}
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nRd++; sigTid=this.threadId;
    const ps=src.toString();
    if(!recentP.some(function(p){return p.toString()===ps;})){ recentP.unshift(src); if(recentP.length>4) recentP.length=4; }
    if(!Ps.some(function(p){return p.toString()===ps;})) Ps.push(src);
    // once we have a couple addrs, lock the band and start arming
    if(!bandBase && Ps.length>=2){ bandBase=bandFor(Ps[0]); send({t:'band', base:bandBase.toString(), from:Ps.map(function(p){return p.toString();})}); }
    send({t:'rd', ord:nRd, tid:sigTid, P:ps, slot16:val, band:bandBase?bandBase.toString():null});
    if(needArm) doArm();
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ if(!done) send({t:'mon', nRd:nRd, nBP:nBP, mode:armedMode, band:bandBase?bandBase.toString():null}); }, 4000);

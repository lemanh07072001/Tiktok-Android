// _mam_producer8.js — FORWARD-window single-enable MAM.
// producer7 proved: single enable() is crash-safe, BUT one-shot on ALREADY-USED pool pages catches the
// wrong accessor (BoringSSL/scudo touch reused pages before the producer). KEY OBSERVATION: the pool
// bump-allocates FORWARD -- producer7's later reads landed at HIGHER addresses than the 12 pages it armed.
// => Fresh forward pages are UNTOUCHED until the producer STRs slot16 into them => on a fresh page the
// producer's write IS the first access => MAM one-shot traps the PRODUCER PC.
// PLAN: hook memcpy(0x172a50) [safe] to watch the pool frontier; after a few reads, arm ONE forward window
// [frontierPage, frontierPage+SPAN) covering where NEXT allocations land; single enable, no re-enable.
// onAccess: report EVERY write with its PC class + 16B value, so we SEE who writes the pool (producer=META).
'use strict';
const SO='libmetasec_ov.so';
const MEMCPY=0x172a50, READBUCKET=0xa0440;
const ARM_AFTER=3;               // arm EARLY (less Interceptor exposure before useful data)
const SPAN=0x40000;              // 256KB forward window (single-enable safe, covers frontier)
const AHEAD=0x2000;              // start slightly ahead of the max-seen pool page
const KNOWN=new Set(['46c03b52742b3f2615a3abdf1636b754','443dfca2529e547fe73a8e0aa4bd2c82',
  '6c109094bc9ab89e050fbd3e2ca6b99e','b29609628ab70d54bb950f2dd9260ff4','b8591fcb8d86ff40ed3989462a588bf1']);
let base=null, lo=null, hi=null, nRd=0, nWr=0, reported=0, armed=false, maxPool=null;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function cls(pc){ if(!pc) return 'null';
  if(pc.compare(lo)>=0&&pc.compare(hi)<0) return 'META:'+pc.sub(base).toString(16);
  const m=Process.findModuleByAddress(pc); if(m) return m.name+':'+pc.sub(m.base).toString(16);
  return 'anon:'+pc.toString(); }
function onAcc(d){
  nWr++;
  if(d.operation!=='write') return;
  let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
  const e=ent(val), pcCls=cls(d.from), isMeta=pcCls.indexOf('META:')===0, known=val&&KNOWN.has(val);
  // report ALL writes (bounded) so we can see the producer among them; flag META & KNOWN loudly
  if(reported<120){ reported++;
    send({t: (isMeta?'META_W': (known?'KNOWN_W':'w')), pc:pcCls, addr:d.address.toString(), val:val, e:e, known:known}); }
}
function armForward(){
  if(armed||!maxPool) return; armed=true;
  const start=pageOf(maxPool).add(AHEAD).and(ptr('0xfffffffffffff000'));
  try{ MemoryAccessMonitor.enable([{base:start, size:SPAN}], {onAccess:onAcc});
       send({t:'armed_forward', start:start.toString(), span:'0x'+SPAN.toString(16), maxPool:maxPool.toString()}); }
  catch(e){ send({t:'err', msg:'MAM.enable '+e}); armed=false; }
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
    if(!maxPool||src.compare(maxPool)>0) maxPool=src;   // track frontier
    if(nRd<=40) send({t:'rd', ord:nRd, src:src.toString(), val:V, known:KNOWN.has(V)});
    if(nRd===ARM_AFTER) armForward();
  }});
  send({t:'info',msg:'mam-producer8 installed base='+base});
  setInterval(function(){ send({t:'mon', nRd:nRd, nWr:nWr, armed:armed, reported:reported}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

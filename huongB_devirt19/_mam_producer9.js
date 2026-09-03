// _mam_producer9.js — ZERO-Interceptor producer localizer.
// producer8 died to the PROBABILISTIC frida-agent SIGSEGV on ChromiumNet0 (x19=0xffff...f000) -- that
// crash hits ANY Interceptor (even the memcpy entry hook; 6/7 only survived by luck). So drop Interceptor.
// KEY: across 3 spawns libmetasec base varied (0x754a2/0x75b6a/0x75b9e) but the slot16 POOL stayed at
// 0x77e4xxxxxx EVERY time -> the pool arena is ASLR-stable ~0x77e4000000. We can target it directly.
// PLAN (no hooks at all):
//   1. poll for libmetasec base (only to classify PC as META in onAccess).
//   2. Memory.scanSync the pool region for a recurring KNOWN slot16 value -> locate the live frontier F.
//   3. arm MAM ONCE forward of F [pageOf(F)+PAD, +SPAN) -- fresh forward pages are untouched, so the
//      producer's STR into a fresh pool buffer == first access == trap => producer PC (META:offset).
//   Single enable, no re-enable (producer6's MAM crash was multi-enable orphaning pages).
'use strict';
const SO='libmetasec_ov.so';
const REGION=ptr('0x77e4000000'), REGION_SZ=0x2000000;   // 32MB scan window covering the stable pool band
const PAD=0x1000, SPAN=0x80000;                          // arm 512KB just ahead of the scanned frontier
const KNOWN=['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82'];
const KSET=new Set(KNOWN);
let base=null, lo=null, hi=null, nWr=0, reported=0, armed=false, scans=0, frontier=null;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function cls(pc){ if(!pc) return 'null';
  if(base&&pc.compare(lo)>=0&&pc.compare(hi)<0) return 'META:'+pc.sub(base).toString(16);
  const m=Process.findModuleByAddress(pc); if(m) return m.name+':'+pc.sub(m.base).toString(16);
  return 'anon:'+pc.toString(); }
function onAcc(d){
  nWr++;
  if(d.operation!=='write') return;
  let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
  const e=ent(val), pcCls=cls(d.from), isMeta=pcCls.indexOf('META:')===0, known=val&&KSET.has(val);
  if(reported<120){ reported++;
    send({t:(isMeta?'META_W':(known?'KNOWN_W':'w')), pc:pcCls, addr:d.address.toString(), val:val, e:e, known:known}); }
}
function armForward(F){
  if(armed) return; armed=true; frontier=F;
  const start=pageOf(F).add(PAD).and(ptr('0xfffffffffffff000'));
  try{ MemoryAccessMonitor.enable([{base:start, size:SPAN}], {onAccess:onAcc});
       send({t:'armed_forward', start:start.toString(), span:'0x'+SPAN.toString(16), frontier:F.toString()}); }
  catch(e){ send({t:'err', msg:'MAM.enable '+e}); armed=false; }
}
function scanOnce(){
  if(armed) return;
  scans++;
  for(const kv of KNOWN){
    // build byte pattern "aa bb cc ..." for scanSync
    let pat=''; for(let i=0;i<32;i+=2){ pat+=(i?' ':'')+kv.substr(i,2); }
    let res=[]; try{ res=Memory.scanSync(REGION, REGION_SZ, pat); }catch(e){}
    if(res.length){
      // pick the highest address hit as the frontier (bump-allocate marches forward)
      let hiAddr=res[0].address; for(const r of res){ if(r.address.compare(hiAddr)>0) hiAddr=r.address; }
      send({t:'scan_hit', val:kv, n:res.length, at:hiAddr.toString(), scans:scans});
      armForward(hiAddr);
      return;
    }
  }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); }
  send({t:'info',msg:'mam-producer9 installed base='+base+' (ZERO interceptor)'});
  const sc=setInterval(function(){ if(armed){ clearInterval(sc); return; } scanOnce(); }, 500);
  setInterval(function(){ send({t:'mon', nWr:nWr, armed:armed, scans:scans, reported:reported}); }, 5000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=setInterval(function(){ if(Process.findModuleByName(SO)){ clearInterval(t); install(); } }, 200); }

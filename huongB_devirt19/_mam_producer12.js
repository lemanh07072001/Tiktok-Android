// _mam_producer12.js — ZERO-Interceptor + fixed pool window + re-protect (defeat one-shot).
// Every Interceptor script dies ~1/3 of runs to the frida-agent ChromiumNet0 crash (producer8/11 lost the
// flip before arming). So NO Interceptor at all. The pool is ASLR-stable: every run with data had pool in
// 0x77e4bxxxxx..0x77e4fxxxxx (producer8/11 both hit 0x77e4e). Arm MAM directly on that slice.
// One-shot is defeated by re-protecting each faulting page to 'r--' inside onAccess so the NEXT write
// re-traps: scudo writes the chunk header first (libc:56e64) -> we re-protect -> the producer's slot16 STR
// re-traps -> details.from = producer PC (META:offset). This run also TESTS whether re-protect composes
// with frida MAM (if MAM won't re-handle a re-protected page we'll see an app SEGV_ACCERR instead of hits).
'use strict';
const SO='libmetasec_ov.so';
const BAND_LO=ptr('0x77e4000000'), BAND_HI=ptr('0x77e5000000');
const WANT=0x40000;   // arm up to 256KB, sliced from a fully-mapped rw- anon range (avoid inaccessible pages)
const KNOWN=new Set(['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e',
  'b8591fcb8d86ff40ed3989462a588bf1','b29609628ab70d54bb950f2dd9260ff4','443dfca2529e547fe73a8e0aa4bd2c82']);
let base=null, lo=null, hi=null, nAcc=0, nW=0, reported=0, metaHits=0, disabled=false, reGuards=0;
const GUARD_MAX=8, GLOBAL_GUARD_MAX=4000;   // bound the re-protect storm
const gcnt=new Map();                        // per-page re-guard counter
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function pageOf(p){ return p.and(ptr('0xfffffffffffff000')); }
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function isScudoHdr(v){ return v && (v.substr(0,4)==='0280' || v.substr(0,4)==='0200') && v.substr(16)==='0000000000000000'; }
function cls(pc){ if(!pc) return 'null';
  if(base&&pc.compare(lo)>=0&&pc.compare(hi)<0) return 'META:'+pc.sub(base).toString(16);
  const m=Process.findModuleByAddress(pc); if(m) return m.name+':'+pc.sub(m.base).toString(16);
  return 'anon:'+pc.toString(); }
function reguard(addr){
  if(reGuards>=GLOBAL_GUARD_MAX) return;
  const pk=pageOf(addr).toString(); const n=gcnt.get(pk)||0; if(n>=GUARD_MAX) return;
  gcnt.set(pk,n+1); reGuards++;
  try{ Memory.protect(pageOf(addr), 0x1000, 'r--'); }catch(e){}   // next write to this page re-traps
}
function onAcc(d){
  nAcc++;
  if(disabled) return;
  if(d.operation==='write'){
    nW++;
    let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
    const e=ent(val), pcCls=cls(d.from), isMeta=pcCls.indexOf('META:')===0, known=val&&KNOWN.has(val);
    if(isMeta || known || (e>=13 && !isScudoHdr(val))){
      if(reported<200){ reported++;
        send({t:(isMeta?'META_W':(known?'KNOWN_W':'hiEW')), pc:pcCls, addr:d.address.toString(), val:val, e:e, known:known}); }
      // a META write OR a KNOWN-value write is the producer/its data path -> capture PC then STOP
      if(isMeta || known){ metaHits++;
        if(!disabled){ disabled=true; try{MemoryAccessMonitor.disable();}catch(_){}
          send({t:'DISABLED_producer', pc:pcCls, val:val, known:known, isMeta:isMeta}); return; } }
    }
    reguard(d.address);
  } else {
    reguard(d.address);
  }
}
function pickRanges(){
  // enumerateRanges('rw-') returns only ACCESSIBLE ranges -> slices from them are never 'inaccessible'.
  const cand=Process.enumerateRanges('rw-').filter(function(r){
    if(r.file) return false;
    return r.base.compare(BAND_LO)>=0 && r.base.compare(BAND_HI)<0 && r.size>=0x4000;
  });
  cand.sort(function(a,b){ return b.size-a.size; });
  send({t:'ranges', n:cand.length, top:cand.slice(0,6).map(function(r){return r.base.toString()+':0x'+r.size.toString(16);})});
  if(!cand.length) return null;
  const r=cand[0];
  return [{base:r.base, size:Math.min(r.size, WANT)}];
}
function arm(){
  const ranges=pickRanges();
  if(!ranges){ send({t:'err', msg:'no rw- anon range in 0x77e4 band'}); return; }
  try{ MemoryAccessMonitor.enable(ranges, {onAccess:onAcc});
       send({t:'armed', base:ranges[0].base.toString(), size:'0x'+ranges[0].size.toString(16)}); }
  catch(e){ send({t:'err', msg:'MAM.enable '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); return true; }
  send({t:'info',msg:'mam-producer12 installed base='+base+' (ZERO interceptor), arming in 9s'});
  setTimeout(arm, 9000);   // let the 0x77e4 pool arena grow before choosing the biggest rw- range
  setInterval(function(){ send({t:'mon', nAcc:nAcc, nW:nW, metaHits:metaHits, reported:reported, disabled:disabled, reGuards:reGuards, pages:gcnt.size}); }, 3000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=setInterval(function(){ if(Process.findModuleByName(SO)){ clearInterval(t); install(); } }, 200); }

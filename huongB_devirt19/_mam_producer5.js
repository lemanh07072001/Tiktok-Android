// _mam_producer5.js — MAM-ONLY producer localizer (ZERO Interceptor).
// WHY: any frida Interceptor/Stalker hook crashes this app probabilistically -> identical SIGSEGV in
// frida-agent on the ChromiumNet0 thread (bad per-thread TLS 0x8000 deref +8 under PAC), BEFORE our JS
// runs. producer2 (hook 0x172a50) and producer3 (hook 0xa0430) both died there; baseline only survived by
// luck. MemoryAccessMonitor is mprotect+SIGSEGV based -> NO trampolines, NO per-thread interceptor state
// -> immune to that crash class (prior MAM tests never crashed).
// MODEL: the producer STRs the 16B slot16 DIRECTLY into a fresh pool buffer (0x7d0c.. band) BEFORE the
// a0440 read-path copies it out. That store == a WRITE of 16 high-entropy bytes from a libmetasec PC.
// So: arm MAM for WRITES over the heap band that holds the pool(0x7d) + keystore arena(0x7e); the first
// access to each fresh page traps once (one-shot) -> details.from == the writing PC. A write whose value
// is high-entropy (or matches a KNOWN deterministic slot16) from a libmetasec PC == the producer.
'use strict';
const SO='libmetasec_ov.so';
const LOB=ptr('0x7c0000000000'), HIB=ptr('0x7f0000000000'); // heap band to watch (pool 0x7d, arena 0x7e)
// deterministic slot16 values seen across multiple AVD register bursts -> definitive producer confirmation
const KNOWN=new Set(['46c03b52742b3f2615a3abdf1636b754','443dfca2529e547fe73a8e0aa4bd2c82',
  '4c6b995344026d0cac8df6620a3a96ca','58f2de715ba986da8d78155894b9a7aa','d951198a57936f91a3d14cecd63cbb6a']);
let base=null, lo=null, hi=null, nWr=0, nAcc=0, reported=0, armedRanges=0, armedBytes=0, hits=[];
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function ent(v){ if(!v||v==='00'.repeat(16))return 0; let pr=0; for(let i=0;i<32;i+=2){const c=parseInt(v.substr(i,2),16); if(c>=0x20&&c<=0x7e)pr++;} return 16-pr; }
function cls(pc){ if(!pc) return 'null';
  if(pc.compare(lo)>=0&&pc.compare(hi)<0) return 'META:'+pc.sub(base).toString(16);
  const m=Process.findModuleByAddress(pc); if(m) return m.name+':'+pc.sub(m.base).toString(16);
  return 'anon:'+pc.toString(); }
function bandRanges(){
  return Process.enumerateRanges('rw-').filter(r=>{
    if(r.file) return false;                       // anonymous only (heap/arena/pool)
    if(r.base.compare(LOB)<0||r.base.compare(HIB)>=0) return false;
    return true;
  });
}
function arm(){
  const rs=bandRanges();
  armedRanges=rs.length; armedBytes=rs.reduce((a,r)=>a+r.size,0);
  try{
    MemoryAccessMonitor.enable(rs.map(r=>({base:r.base,size:r.size})), { onAccess(d){
      nAcc++;
      if(d.operation!=='write') return;
      nWr++;
      let val=null; try{ val=hx(d.address.readByteArray(16)); }catch(e){}
      const e=ent(val), pcCls=cls(d.from), isMeta=pcCls.indexOf('META:')===0, known=val&&KNOWN.has(val);
      if(known || (isMeta && e>=10)){
        const rec={pc:pcCls, addr:d.address.toString(), val:val, e:e, known:known};
        hits.push(rec);
        if(reported<80){ reported++; send({t:'HIT', pc:pcCls, addr:rec.addr, val:val, e:e, known:known}); }
      }
    }});
    send({t:'armed', ranges:armedRanges, mb:Math.round(armedBytes/1048576)});
  }catch(e){ send({t:'err', msg:'MAM.enable '+e}); }
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  if(typeof MemoryAccessMonitor==='undefined'){ send({t:'err',msg:'no MemoryAccessMonitor'}); return true; }
  send({t:'info',msg:'mam-producer5 installed base='+base});
  arm();
  // re-arm periodically: pool buffers land in pages mmap'd AFTER enable; MAM snapshots ranges at enable time
  setInterval(arm, 3000);
  setInterval(function(){ send({t:'mon', nAcc:nAcc, nWr:nWr, hits:hits.length, ranges:armedRanges}); }, 5000);
  return true;
}
// fully Interceptor-free: poll for libmetasec load instead of hooking android_dlopen_ext
if(Process.findModuleByName(SO)) install();
else { const t=setInterval(function(){ if(Process.findModuleByName(SO)){ clearInterval(t); install(); } }, 200); }

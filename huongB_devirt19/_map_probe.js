// _map_probe.js — SAFE memory-map probe (no Interceptor, no MAM). Enumerate anonymous rw- ranges to
// locate the scudo heap band that holds the slot16 pool on THIS AVD run (ASLR differs from ce0516's 0x7d0c).
'use strict';
const SO='libmetasec_ov.so';
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  send({t:'info', base:m.base.toString(), size:'0x'+m.size.toString(16)});
  function dump(){
    const rs=Process.enumerateRanges('rw-').filter(r=>!r.file);
    // group by top 16 bits (band) to see where the heap clusters
    const bands={};
    rs.forEach(r=>{ const b=r.base.shr(32).toString(16); bands[b]=(bands[b]||0)+r.size; });
    const bandArr=Object.keys(bands).map(k=>({band:'0x'+k+'xxxxxxxx', mb:Math.round(bands[k]/1048576)})).sort((a,b)=>b.mb-a.mb);
    // top 25 largest individual anon rw ranges
    const top=rs.slice().sort((a,b)=>b.size-a.size).slice(0,25)
                .map(r=>({base:r.base.toString(), mb:(r.size/1048576).toFixed(2)}));
    send({t:'map', nAnonRW:rs.length, bands:bandArr, top:top});
  }
  dump();
  setInterval(dump, 6000);
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=setInterval(function(){ if(Process.findModuleByName(SO)){ clearInterval(t); install(); } }, 200); }

// _slot16_scan.js — Locate the STABLE (cache/seed) copy of the deterministic slot16.
// The value 46c03b52742b3f2615a3abdf1636b754 repeats across requests & devices -> it is CACHED somewhere.
// When a reader reports that value, scan all RW memory for the 16-byte pattern and report every live copy,
// tagging module-resident ones (SELF+off = libmetasec .bss/global). A stable module-global copy = the
// producer's output/cache buffer; watching it (proven 8-byte WP) will trap the PRODUCER store.
'use strict';
const SO='libmetasec_ov.so';
const COPY=0x172a50, READBUCKET=0xa0440;
const TARGET='46c03b52742b3f2615a3abdf1636b754';
const PATTERN='46 c0 3b 52 74 2b 3f 26 15 a3 ab df 16 36 b7 54';
let base=null, lo=null, hi=null, done=false, nRd=0;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function tag(addr){
  const p=ptr(addr.toString());
  if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);
  const m=Process.findModuleByAddress(p);
  if(m) return m.name+'+0x'+p.sub(m.base).toString(16);
  const r=Process.findRangeByAddress(p);
  return (r?('['+r.protection+']'):'[anon]')+' '+p.toString();
}
function doScan(P){
  const ranges=Process.enumerateRanges('rw-');
  let hits=[], scanned=0, skipped=0;
  for(let i=0;i<ranges.length && hits.length<80;i++){
    const r=ranges[i];
    if(r.size>96*1024*1024){ skipped++; continue; }     // skip huge mappings
    let found=[];
    try{ found=Memory.scanSync(r.base, r.size, PATTERN); }catch(e){}
    scanned++;
    for(let j=0;j<found.length;j++){
      const a=found[j].address;
      hits.push({addr:a.toString(), tag:tag(a), isP:(a.toString()===P), inSelf:inSelf(a)});
    }
  }
  send({t:'SCAN', target:TARGET, P:P, nHits:hits.length, scannedRanges:scanned, skipped:skipped, hits:hits});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString(), size:m.size});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(done) return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nRd++;
    if(val===TARGET && !done){
      done=true;
      send({t:'match', ord:nRd, P:src.toString(), val:val});
      doScan(src.toString());
    }
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ if(!done) send({t:'mon', nRd:nRd}); }, 5000);

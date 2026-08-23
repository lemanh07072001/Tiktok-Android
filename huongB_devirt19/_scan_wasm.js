'use strict';
let done=false;
function scan(){
  if(done)return;done=true;
  const results=[];
  const ranges=Process.enumerateRanges('r--');
  let scanned=0;
  for(const r of ranges){
    if(r.size>0x4000000)continue; // skip huge ranges
    try{
      Memory.scanSync(r.base,r.size,'00 61 73 6d 01 00 00 00').forEach(function(m){
        results.push(m.address.toString());
      });
      scanned++;
    }catch(e){}
  }
  send({t:'WASM_SCAN',found:results.length,addrs:results.slice(0,20),ranges_scanned:scanned});
}
// wait for libmetasec to load then scan after a delay
const SO='libmetasec_ov.so';
function wait(){
  const m=Process.findModuleByName(SO);
  if(m){ setTimeout(scan,8000); send({t:'info',msg:'metasec loaded, scanning in 8s'}); }
  else setTimeout(wait,500);
}
wait();

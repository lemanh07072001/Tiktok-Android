'use strict';
let done=false;
function scan(){
  if(done)return;done=true;
  const results=[];
  const ranges=Process.enumerateRanges('rw-');  // WASM decompressed into RW heap
  let scanned=0;
  for(const r of ranges){
    if(r.size>0x2000000)continue;
    try{
      Memory.scanSync(r.base,r.size,'00 61 73 6d 01 00 00 00').forEach(function(m){
        // read 32 bytes to confirm
        let hdr='';try{const u=new Uint8Array(m.address.readByteArray(32));for(let i=0;i<u.length;i++)hdr+=('0'+u[i].toString(16)).slice(-2);}catch(e){}
        results.push({addr:m.address.toString(),hdr:hdr});
      });
      scanned++;
    }catch(e){}
  }
  send({t:'WASM_SCAN',found:results.length,hits:results.slice(0,10),ranges_scanned:scanned});
}
const SO='libmetasec_ov.so';
function wait(){
  const m=Process.findModuleByName(SO);
  if(m){send({t:'info',msg:'loaded, scan in 6s'});setTimeout(scan,6000);}
  else setTimeout(wait,500);
}
wait();

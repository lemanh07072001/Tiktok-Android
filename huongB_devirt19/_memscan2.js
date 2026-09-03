'use strict';
const A_HEX='c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163';
const S16_HEX='6c109094bc9ab89e050fbd3e2ca6b99e';
function scanFor(hexpat,label){
  const ranges=Process.enumerateRanges('rw-');
  let hits=0; const out=[]; let scanned=0;
  for(const r of ranges){
    scanned++;
    try{
      const found=Memory.scanSync(r.base, r.size, hexpat);
      for(const f of found){
        hits++;
        out.push({addr:f.address.toString(), prot:r.protection,
          file:(r.file?r.file.path:null), foff:(r.file?r.file.offset:null),
          rbase:r.base.toString(), rsize:r.size});
        if(hits>=16) break;
      }
    }catch(e){}
    if(hits>=16) break;
  }
  send({t:'SCAN', label:label, pat:hexpat, hits:hits, nranges:scanned, out:out});
}
function go(){
  send({t:'scanning', nrw:Process.enumerateRanges('rw-').length});
  scanFor(A_HEX,'device_key_A');
  scanFor(S16_HEX,'slot16_privacy');
  send({t:'done'});
}
setTimeout(go, 9000);
setInterval(()=>send({t:'mon'}),3000);

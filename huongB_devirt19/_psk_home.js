// _psk_home.js — find the PSK's HOME (persistent storage) by scanning memory for the known PSK bytes.
// PSK = b2a9d40c...  (located via message-diff). It's copied into each compression's x1+0x30 (transient);
// its HOME = a device-stable rw- heap/data location. Once we know the home region, we hook writes to it
// (next step) to catch the PSK-GENERATION (fingerprint -> PSK).
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, F=0x186420;
const PSK32='b2a9d40c622aedce93a5e22f03780a67599f816e6a5c6c6e6dfca3e4eb6b632d';
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path.split('/').pop():'anon')+' '+r.protection; }catch(e){} return '?'; }
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let done=false;
function scan(){
  const patStr=PSK32.match(/../g).join(' '); const hits=[];
  const ranges=Process.enumerateRanges('rw-');
  for(const r of ranges){ if(r.size>64*1024*1024) continue;
    try{ const found=Memory.scanSync(r.base,r.size,patStr);
      for(const f of found){ hits.push({at:f.address.toString(), region:region(f.address), before16:hx(f.address.sub(16),16), after16:hx(f.address.add(32),16)}); if(hits.length>=40) break; } }catch(e){}
    if(hits.length>=40) break; }
  return hits;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(done) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==F) return; }catch(e){ return; }
    done=true;
    const hits=scan();
    send({t:'home', npsk:hits.length, hits:hits});
  }});
  send({t:'info',msg:'psk-home installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

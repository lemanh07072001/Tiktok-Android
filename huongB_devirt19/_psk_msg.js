// _psk_msg.js — capture the MESSAGE bytes fed to compression 0x186420 across invocations of ONE hash.
// From trace: x1 = 6 pointers (0x00..0x30) + inline data at x1+0x30. Capture x1+0x30 (48B) for the first
// N invocations. Cross-spawn diff: DEVICE-STABLE bytes = PSK-derived; VARYING = seed/state. Also dump the
// pointed message buffer (x1[?]) for a fuller view.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, F=0x186420;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let cnt=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(cnt>=30) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==F) return; }catch(e){ return; }
    cnt++;
    const x1=a[1];
    // inline data at x1+0x30 (48B) + first pointed buffer (x1[0] deref 48B) + x1[3] (often the state/msg)
    let ptrs=[]; for(let i=0;i<6;i++){ try{ ptrs.push(ptr(x1).add(i*8).readPointer().toString()); }catch(e){ ptrs.push('?'); } }
    let derefs={};
    for(const i of [0,1,3,4]){ try{ const q=ptr(x1).add(i*8).readPointer(); derefs['q'+i]=hx(q,48); }catch(e){} }
    send({t:'msg', n:cnt, x1:x1.toString(), inline:hx(x1.add(0x30),48), ptrs:ptrs, derefs:derefs});
  }});
  send({t:'info',msg:'psk-msg installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

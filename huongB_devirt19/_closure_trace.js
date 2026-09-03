// _closure_trace.js — hook closure invoker 0x9bf88 to locate slot16's heap buffer,
// then use MemoryAccessMonitor (software watchpoint) to catch the WRITE (F's output store).
'use strict';
const SO='libmetasec_ov.so';
const CLOSURE=0x9bf88;      // x0=closure struct: [0x00]=concat fn, [0x10]=query ptr, [0x18]=slot16 ptr
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; let seen={}; let armed=false; let count=0;
  Interceptor.attach(base.add(CLOSURE),{onEnter(){
    const c=this.context; let x0=c.x0;
    let slotPtr=null, qPtr=null, concat=null, slotVal=null;
    try{ concat=x0.readPointer(); qPtr=x0.add(0x10).readPointer(); slotPtr=x0.add(0x18).readPointer(); }catch(e){ return; }
    try{ slotVal=hx(slotPtr.readByteArray(16)); }catch(e){}
    if(!slotVal || slotVal==='00000000000000000000000000000000') return;   // only nonzero slot16
    count++;
    const key=slotPtr.toString();
    send({t:'closure', n:count, concat:concat.sub(base).toString(), slotPtr:key,
          slotOff:'heap', slot16:slotVal, qPtr:qPtr.toString(),
          concatIsExpected:(concat.sub(base).toString(16)==='150348')});
  }});
  send({t:'info',msg:'closure-trace installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

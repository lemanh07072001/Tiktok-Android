// _diag.js — capture the producer's INTERMEDIATE working state to localize the reimplementation bug.
// Probes (once per call, first hit): 0xa0e00 iv+args; 0xa0ed8 post-LoopA regs; 0xa0f70 pre-whiten regs;
// 0xa0f90 tables+out. Emit full combined record for the first few calls.
'use strict';
const SO='libmetasec_ov.so';
const ENTRY=0xa0748, IVLOAD=0xa0e00, POSTA=0xa0ed8, PREWH=0xa0f70, STORE=0xa0f90;
let base=null; let nEmit=0, done=false; const MAX=4;
const sc=new Map();  // tid -> {iv, postA, preWh, tables, x9}
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,n){try{return hx(p.readByteArray(n));}catch(e){return null;}}
function regs(ctx,hi){const o={};for(let i=0;i<=hi;i++){try{o['x'+i]=ctx['x'+i].and(ptr('0xffffffff')).toString();}catch(e){o['x'+i]=null;}}return o;}
function get(tid){let s=sc.get(tid);if(!s){s={};sc.set(tid,s);}return s;}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(IVLOAD),{onEnter(){if(done)return;const s=get(this.threadId);s.iv=rh(this.context.x9.add(8),32);s.postA=null;s.preWh=null;}});
  Interceptor.attach(base.add(POSTA),{onEnter(){if(done)return;const s=get(this.threadId);if(s.postA)return;s.postA=regs(this.context,28);}});
  Interceptor.attach(base.add(PREWH),{onEnter(){if(done)return;const s=get(this.threadId);if(s.preWh)return;s.preWh=regs(this.context,28);}});
  Interceptor.attach(base.add(STORE),{onEnter(){
    if(done)return;const s=get(this.threadId);const x9=this.context.x9,sp=this.context.sp;
    s.tables=rh(sp,0x300); s.x9=x9.toString();
  }});
  Interceptor.attach(base.add(ENTRY),{onLeave(){
    if(done)return;const tid=this.threadId;const s=sc.get(tid)||{};sc.delete(tid);
    if(!s.iv||!s.tables)return;
    const out=rh(ptr(s.x9).add(8),32);
    if(nEmit>=MAX){done=true;send({t:'stopped'});return;}
    nEmit++;
    send({t:'DIAG',n:nEmit,iv:s.iv,out:out,tables:s.tables,postA:s.postA,preWh:s.preWh});
    if(nEmit>=MAX){done=true;send({t:'stopped'});}
  }});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

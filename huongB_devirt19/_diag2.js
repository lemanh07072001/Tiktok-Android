// _diag2.js — capture Loop A top (0xa0e40) register state on the first TWO hits (i=0 init, i=1 after 1 round),
// to pin the reimplementation divergence to a single iteration. Also grab iv+tables for offline replay.
'use strict';
const SO='libmetasec_ov.so';
const ENTRY=0xa0748, IVLOAD=0xa0e00, LA_TOP=0xa0e40, STORE=0xa0f90;
let base=null,nEmit=0,done=false;const MAX=2;
const sc=new Map();
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,n){try{return hx(p.readByteArray(n));}catch(e){return null;}}
function regs(ctx){const o={};for(let i=0;i<=28;i++){try{o['x'+i]=ctx['x'+i].and(ptr('0xffffffff')).toString();}catch(e){o['x'+i]=null;}}return o;}
function get(t){let s=sc.get(t);if(!s){s={hits:[]};sc.set(t,s);}return s;}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;base=m.base;send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(IVLOAD),{onEnter(){if(done)return;const s=get(this.threadId);s.iv=rh(this.context.x9.add(8),32);s.hits=[];}});
  Interceptor.attach(base.add(LA_TOP),{onEnter(){if(done)return;const s=get(this.threadId);if(s.hits.length<2)s.hits.push(regs(this.context));}});
  Interceptor.attach(base.add(STORE),{onEnter(){if(done)return;const s=get(this.threadId);s.tables=rh(this.context.sp,0x300);s.x9=this.context.x9.toString();}});
  Interceptor.attach(base.add(ENTRY),{onLeave(){if(done)return;const s=sc.get(this.threadId)||{};sc.delete(this.threadId);
    if(!s.iv||!s.tables||!s.hits||s.hits.length<2)return;const out=rh(ptr(s.x9).add(8),32);
    if(nEmit>=MAX){done=true;send({t:'stopped'});return;}nEmit++;
    send({t:'DIAG2',n:nEmit,iv:s.iv,out:out,tables:s.tables,hit0:s.hits[0],hit1:s.hits[1]});
    if(nEmit>=MAX){done=true;send({t:'stopped'});}}});
  return true;
}
if(Process.findModuleByName(SO))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

// _producer_census.js — capture EVERY SM3-producer (0xa0748) call in a cold-start session:
//   per call: (tid, seq, iv@PRELOAD, block64@ENTRY, out@POSTSTORE).
// Goal (route S): reconstruct all messages SM3 hashes; find any that is NOT the query string
// (= session-material whose digest-window may be the slot16 token). Safe hooks only
// (ENTRY 0xa0748, PRELOAD 0xa0de0 pre in-place load, POSTSTORE 0xa0fa0) — see [[frida-x16-clobber-libmetasec]].
'use strict';
const SO='libmetasec_ov.so';
const ENTRY=0xa0748, PRELOAD=0xa0de0, POSTSTORE=0xa0fa0;
let base=null, seq=0, done=false; const MAX=600;
const sc=new Map();
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,n){try{return hx(p.readByteArray(n));}catch(e){return null;}}
function get(t){let s=sc.get(t);if(!s){s={};sc.set(t,s);}return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(ENTRY),{onEnter(){if(done)return;const c=this.context,s=get(this.threadId);
    s.block = rh(c.x1, 64);           // this 64-byte message block
  }});
  Interceptor.attach(base.add(PRELOAD),{onEnter(){if(done)return;const c=this.context,s=get(this.threadId);
    try{s.iv=rh(c.x9.add(8),32);}catch(e){}
  }});
  Interceptor.attach(base.add(POSTSTORE),{onEnter(){if(done)return;const c=this.context;const s=sc.get(this.threadId)||{};sc.delete(this.threadId);
    let out=null;try{out=rh(c.x9.add(8),32);}catch(e){}
    if(done)return; seq++;
    send({t:'C',n:seq,tid:this.threadId,iv:s.iv,block:s.block,out:out});
    if(seq>=MAX){done=true;send({t:'stopped',total:seq});}
  }});
  return true;
}
if(Process.findModuleByName(SO))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

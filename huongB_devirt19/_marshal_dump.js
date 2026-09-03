// _marshal_dump.js — capture, IN THE SAME producer call: the raw message input (x1 / x0-buffer) AND the
// finished tables + iv + out. Goal: decide whether T2 == byteswap(message) directly, and whether the T2
// tail (words 16..63) + T1 are pure functions of the message header (schedule expansion) or raw message.
//
// Safe hook points only (see [[frida-x16-clobber-libmetasec]]):
//   ENTRY     0xa0748  onEnter: x0..x2 regs; msg = readHex(x1, 0x100); buf = readHex(x0, 0x140).
//   PRELOAD   0xa0de0  onEnter: iv=[x9+8,32]; frame = readHex(sp, 0x320) (T0/T1/T2 + source region).
//   POSTSTORE 0xa0fa0  onEnter: out=[x9+8,32]; tables=[sp,0x300]; emit combined record (pair by tid).
'use strict';
const SO='libmetasec_ov.so';
const ENTRY=0xa0748, PRELOAD=0xa0de0, POSTSTORE=0xa0fa0;
let base=null, nEmit=0, done=false; const MAX=8;
const sc=new Map();
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,n){try{return hx(p.readByteArray(n));}catch(e){return null;}}
function get(t){let s=sc.get(t);if(!s){s={};sc.set(t,s);}return s;}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(ENTRY),{onEnter(){if(done)return;const c=this.context,s=get(this.threadId);
    try{s.x0=c.x0.toString();s.x1=c.x1.toString();s.x2=c.x2.toString();}catch(e){}
    s.msg = rh(c.x1, 0x100);           // raw message bytes
    s.buf = rh(c.x0, 0x140);           // output buffer header+state+msg tail
  }});
  Interceptor.attach(base.add(PRELOAD),{onEnter(){if(done)return;const c=this.context,s=get(this.threadId);
    try{s.iv=rh(c.x9.add(8),32);}catch(e){}
    try{s.frame=rh(c.sp,0x320);}catch(e){}
  }});
  Interceptor.attach(base.add(POSTSTORE),{onEnter(){if(done)return;const c=this.context;const s=sc.get(this.threadId)||{};sc.delete(this.threadId);
    let out=null,tables=null;try{out=rh(c.x9.add(8),32);}catch(e){}try{tables=rh(c.sp,0x300);}catch(e){}
    if(nEmit>=MAX){done=true;send({t:'stopped'});return;}nEmit++;
    send({t:'MARSH',n:nEmit,x0:s.x0,x1:s.x1,x2:s.x2,msg:s.msg,buf:s.buf,iv:s.iv,frame:s.frame,out:out,tables:tables});
    if(nEmit>=MAX){done=true;send({t:'stopped'});}
  }});
  return true;
}
if(Process.findModuleByName(SO))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

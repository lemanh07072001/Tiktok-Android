'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
// Log ALL md5(input->output) pairs with full input
Interceptor.attach(base.add(0x15b594),{
  onEnter(){const c=this.context;const len=c.x1.toInt32();this.len=len;this.out=c.x2;this.inp=(len>=0&&len<8192)?hx(c.x0,Math.min(len,4096)):null;},
  onLeave(){if(this.inp!==null){send({t:'M',len:this.len,out:hx(this.out,16),inp:this.inp});}}
});
send({t:'info',msg:'md5log ready'});

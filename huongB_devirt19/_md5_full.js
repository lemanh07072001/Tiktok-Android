'use strict';
const SO='libmetasec_ov.so';
const MD5=0x15b594;
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
let hits=0;
Interceptor.attach(base.add(MD5),{
  onEnter(){ const c=this.context; const len=c.x1.toInt32();
    this.len=len; this.out=c.x2;
    // capture FULL input (up to 4KB)
    this.inp=(len>0&&len<8192)?hx(c.x0,Math.min(len,4096)):null; },
  onLeave(){ if(this.inp&&this.len>=2){ hits++;
    if(hits>60)return;
    const o=hx(this.out,16);
    // Only report md5 of JSON-looking or reasonably-sized inputs (potential bodies)
    const raw=this.inp;
    // check if input starts with { or is a query
    send({t:'MD5F',n:hits,len:this.len,out:o,inhex:raw});
  }}
});
send({t:'info',msg:'md5 full installed'});

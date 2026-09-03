'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.';return s;}catch(e){return'ERR';}}
// stock MD5 one-shot fn 0x15b594 — typically md5(data, len, out) or (out, data, len)
let hits=0;
Interceptor.attach(base.add(0x15b594),{
  onEnter(){
    if(hits>=30)return;
    const c=this.context;
    // try common signatures: x0=data x1=len, or x0=ctx. Capture x0,x1,x2 and their memory.
    this.x0=c.x0;this.x1=c.x1;this.x2=c.x2;
    hits++;
    // if x1 looks like a length (<4096), dump x0 as data
    const len=c.x1.toInt32();
    let data='';
    if(len>0&&len<4096){ data=asc(c.x0,Math.min(len,200)); }
    send({t:'MD5IN',n:hits,x0:c.x0.toString(16),x1:c.x1.toString(16),x2:c.x2.toString(16),len:len,data_preview:data});
  }
});
send({t:'info',msg:'md5 hook installed'});

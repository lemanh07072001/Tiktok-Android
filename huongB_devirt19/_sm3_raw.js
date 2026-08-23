'use strict';
const SO='libmetasec_ov.so';
const SM3=0xa0748;
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
let n=0;
Interceptor.attach(base.add(SM3),{onEnter(){
  n++;
  if(n>15)return;
  const c=this.context;
  // dump state[x0+8..+0x28] and input[x1..+64]
  send({t:'RAW',n:n,
    x0_state:hx(c.x0.add(8),32),
    x1_input:hx(c.x1,64)});
}});
send({t:'info',msg:'sm3 raw installed'});

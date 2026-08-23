'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
const targets={};
let total=0;
Interceptor.attach(base.add(0x9bf88),{onEnter(){
  total++;
  const c=this.context;
  try{
    const t=c.x0.readPointer().sub(base).toInt32()>>>0;
    targets['0x'+t.toString(16)]=(targets['0x'+t.toString(16)]||0)+1;
  }catch(e){}
}});
setInterval(function(){
  send({t:'STAT',total:total,targets:targets});
},2000);
send({t:'info',msg:'closure-all installed'});

'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
// md5 finalize 0x15b43c: x0=ctx, x1=out(16). Capture output of every md5.
const outs=[];
Interceptor.attach(base.add(0x15b43c),{
  onEnter(){this.out=this.context.x1;},
  onLeave(){try{const o=hx(this.out,16);outs.push(o);if(outs.length>200)outs.shift();}catch(e){}}
});
setInterval(function(){if(outs.length){send({t:'FINAL',outs:outs.slice(-30)});}},2000);
send({t:'info',msg:'md5 finalize hook'});

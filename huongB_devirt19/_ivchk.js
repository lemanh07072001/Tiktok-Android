'use strict';
const SO='libmetasec_ov.so';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
const m=Process.findModuleByName(SO); const base=m.base; let n=0;
Interceptor.attach(base.add(0xa0748),{onEnter(){
  if(n>=6) return; n++;
  try{ const st=hx(this.context.x0.add(8).readByteArray(32)); const inp=hx(this.context.x1.readByteArray(16));
    send({t:'i',msg:'SM3 call#'+n+' state='+st+' inp='+inp}); }catch(e){ send({t:'i',msg:'err '+e}); }
}});
send({t:'i',msg:'ivchk installed'});

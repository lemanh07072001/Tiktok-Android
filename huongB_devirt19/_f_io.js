// _f_io.js v2 — read F output at 0x1384e8 (after bl returns), mat at inbuf q2, correlate with serialized slot16.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50, FCALL=0x1384e4, FRET=0x1384e8;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let base=null,lo,hi,seq=0; const st={};   // tid -> {x1,x4,mat}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(FCALL),{onEnter(a){ const c=this.context; const tid=this.threadId;
    let mat=null,q=[]; try{ for(let i=0;i<5;i++) q.push(c.x1.add(i*8).readPointer().toString()); mat=hx(ptr(q[2]),64);}catch(e){}
    st[tid]={x0:c.x0, x1:c.x1.toString(), x4:c.x4, q:q, mat:mat, outpre:hx(c.x4,32)};
  }});
  Interceptor.attach(base.add(FRET),{onEnter(a){ const tid=this.threadId; const s=st[tid]; if(!s) return;
    const outpost=hx(s.x4,32); let dptr=null,dval=null,dval32=null;
    try{ dptr=ptr(s.x4).add(8).readPointer(); dval=hx(dptr,16); dval32=hx(dptr,32);}catch(e){}
    const progOff=(s.x0&&s.x0.compare(lo)>=0&&s.x0.compare(hi)<0)?'0x'+s.x0.sub(base).toString(16):(''+s.x0);
    send({t:'F', seq:++seq, prog:progOff, mat:s.mat, outpre:s.outpre, outpost:outpost, dptr:dptr?dptr.toString():null, dval:dval, dval32:dval32});
    delete st[tid];
  }});
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(a[2].toInt32()!==16) return; let ra=null; try{ra=this.returnAddress;}catch(e){}
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!=='a0440') return;
    let sv=hx(a[1],16); if(!sv||sv==='00'.repeat(16)) return;
    send({t:'ser', seq:++seq, slot16:sv});
  }});
  send({t:'info',msg:'f-io2 installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

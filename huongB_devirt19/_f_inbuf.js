// _f_inbuf.js — pin F's input-buffer layout. Send at onEnter (VM call doesn't return cleanly to onLeave).
'use strict';
const SO='libmetasec_ov.so', FCALL=0x1384e4, FRET=0x1384e8;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; let n=0, seq={};
  Interceptor.attach(base.add(FCALL),{
    onEnter(){
      if(n>=10) return; const c=this.context; n++;
      const x1=c.x1; const sp=c.sp; const tid=this.threadId;
      const inbuf=rd(x1,48);
      const derefs=[];
      for(let i=0;i<5;i++){ try{ const p=x1.add(i*8).readPointer(); derefs.push({q:i, ptr:p.toString(), data:rd(p,64)});}catch(e){derefs.push({q:i,err:''+e});} }
      seq[tid]={inbuf:inbuf, derefs:derefs, sp:sp.toString(), n:n};
      send({t:'f_enter', n:n, tid:tid, inbuf:inbuf, derefs:derefs, sp:sp.toString()});
    }
  });
  Interceptor.attach(base.add(FRET),{
    onEnter(){
      const tid=this.threadId; const s=seq[tid]; if(!s) return;
      const slot=rd(this.context.sp.add(0x20),16);   // outbuf = sp+0x20
      send({t:'f_ret', tid:tid, n:s.n, slot16:slot});
      delete seq[tid];
    }
  });
  send({t:'info',msg:'f-inbuf installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

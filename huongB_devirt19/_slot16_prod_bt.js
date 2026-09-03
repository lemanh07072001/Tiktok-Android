'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let base=null,lo,hi; let done=0;
function soReg(a){ try{ if(a.compare(lo)>=0&&a.compare(hi)<0) return 'libmetasec+0x'+a.sub(base).toString(16);}catch(e){}
  try{const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection;}catch(e){} return null; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(done>=4) return;
    const len=a[2].toInt32(); if(len!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra) return;
    const raoff=ra.compare(lo)>=0&&ra.compare(hi)<0 ? ra.sub(base).toString(16) : null;
    if(raoff!=='a0440') return;
    done++;
    const src=a[1];
    const around=hx(src.sub(0x40),0xC0);
    // manual SO-range stack walk (safe)
    const stack=[]; try{ const sp=this.context.sp;
      for(let o=0;o<0x800 && stack.length<24;o+=8){ let v; try{v=sp.add(o).readPointer();}catch(e){break;}
        if(v.compare(lo)>=0&&v.compare(hi)<0) stack.push('libmetasec+0x'+v.sub(base).toString(16)); } }catch(e){}
    send({t:'prod', src:src.toString(), srcRegion:soReg(src), around:around, ra:'0x'+raoff, stack:stack});
  }});
  send({t:'info',msg:'prod-bt2 installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

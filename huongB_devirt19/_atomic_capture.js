'use strict';
const SO='libmetasec_ov.so';
let installed=false,cnt=0;
function ru64(p){try{if(p.isNull())return'NULL';return p.readU64().toString(16).padStart(16,'0');}catch(e){return'ERR';}}
function rp(p,n){try{if(p.isNull())return'NULL';const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function install(base){
  if(installed)return;installed=true;
  Interceptor.attach(base.add(0x55950),{onEnter(){
    if(cnt>=3)return;cnt++;
    const c=this.context;
    const regs={};
    for(let i=0;i<=30;i++){try{regs['x'+i]=c['x'+i].toString(16);}catch(e){}}
    regs.fp=c.fp.toString(16);regs.lr=c.lr.toString(16);regs.sp=c.sp.toString(16);
    let regfile='';try{for(let i=0;i<32;i++)regfile+=ru64(c.x24.add(i*8));}catch(e){}
    let bc='',bcp='';try{const bp=c.x23.readPointer();bcp=bp.toString(16);bc=rp(bp,512);}catch(e){}
    const pred=ru64(c.fp.sub(0x58));
    const stack=rp(c.sp,0xa0);
    // x30 = lr in dispatch loop context (the movk chain uses x30)
    send({t:'ATOM',n:cnt,base:base.toString(16),pred_fp58:pred,
      regs:regs,regfile:regfile,bcptr:bcp,bytecode:bc,stack_sp:stack});
  }});
  send({t:'info',msg:'atomic capture installed'});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

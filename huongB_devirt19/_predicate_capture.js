'use strict';
const SO='libmetasec_ov.so';
let installed=false;
function ru64(p){try{if(p.isNull())return'NULL';return p.readU64().toString(16).padStart(16,'0');}catch(e){return'ERR';}}
function rp(p,n){try{if(p.isNull())return'NULL';const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}

function install(base){
  if(installed)return; installed=true;
  let n=0;
  Interceptor.attach(base.add(0x55950),{onEnter(){
    n++;
    if(n>3)return;
    const c=this.context;
    // [fp-0x58] opaque predicate, [x7+0xe0] handler table base
    const fp=c.fp, x7=c.x7;
    const pred = ru64(fp.sub(0x58));
    const htbl = ru64(x7.add(0xe0));
    // also capture the full context for Unicorn seeding
    const regs={};
    for(let i=0;i<=30;i++){try{regs['x'+i]=c['x'+i].toString(16);}catch(e){}}
    regs.fp=c.fp.toString(16); regs.lr=c.lr.toString(16); regs.sp=c.sp.toString(16);
    // regfile at x24, bytecode ptr at x23
    let regfile='';
    try{for(let i=0;i<32;i++)regfile+=ru64(c.x24.add(i*8));}catch(e){regfile='ERR';}
    let bc='',bcptr='';
    try{const bp=c.x23.readPointer();bcptr=bp.toString(16);bc=rp(bp,256);}catch(e){bc='ERR';}
    // stack dump around sp (the dispatch reads sp+0x38, sp+0x40, sp+0x10, sp+0x18, sp+0x20)
    let stack=rp(c.sp,0xa0);
    send({t:'PRED',n:n,base:base.toString(16),pred_fp58:pred,htbl_x7e0:htbl,
      regs:regs,regfile:regfile,bcptr:bcptr,bytecode:bc,stack_sp:stack});
  }});
  send({t:'info',msg:'predicate capture INSTALLED base='+base});
}
const m=Process.findModuleByName(SO);
if(m) install(m.base);
else {const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

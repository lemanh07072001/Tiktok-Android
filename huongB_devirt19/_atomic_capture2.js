'use strict';
const SO='libmetasec_ov.so';
let installed=false,cnt=0;
// Read register as full 64-bit hex via NativePointer (avoids Number precision loss)
function r64(np){try{return np.toString();}catch(e){return'ERR';}}  // NativePointer.toString() = full hex
function ru64(p){try{if(p.isNull())return'NULL';return p.readU64().toString();}catch(e){return'ERR';}}
function rp(p,n){try{if(p.isNull())return'NULL';const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function install(base){
  if(installed)return;installed=true;
  Interceptor.attach(base.add(0x55950),{onEnter(){
    if(cnt>=3)return;cnt++;
    const c=this.context;
    const regs={};
    // ctx registers are NativePointer -> toString() gives full 0x... hex
    for(let i=0;i<=30;i++){try{regs['x'+i]=c['x'+i].toString();}catch(e){}}
    regs.fp=c.fp.toString();regs.lr=c.lr.toString();regs.sp=c.sp.toString();
    regs.x29=c.x29?c.x29.toString():c.fp.toString();
    let regfile='';try{for(let i=0;i<32;i++)regfile+=ru64(c.x24.add(i*8))+',';}catch(e){}
    let bc='',bcp='';try{const bp=c.x23.readPointer();bcp=bp.toString();bc=rp(bp,512);}catch(e){}
    const pred=ru64(c.fp.sub(0x58));
    const stack=rp(c.sp,0x100);
    send({t:'ATOM2',n:cnt,base:base.toString(),pred_fp58:pred,
      regs:regs,regfile:regfile,bcptr:bcp,bytecode:bc,stack_sp:stack});
  }});
  send({t:'info',msg:'atomic2 installed'});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

'use strict';
const SO='libmetasec_ov.so';
let installed=false, done=false;
function ru64(p){try{if(p.isNull())return'NULL';return p.readU64().toString(16).padStart(16,'0');}catch(e){return'ERR';}}
function rp(p,n){try{if(p.isNull())return'NULL';const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR:'+e.message;}}
function install(base){
  if(installed)return; installed=true;
  // hook at 0x55904 (ldr x8,[x8]) — capture the ACTUAL table address x8 before load
  Interceptor.attach(base.add(0x55900),{onEnter(){    // add x8,x9,x8<<3 done at 55900; after this x8=table entry addr
    if(done)return; done=true;
    const c=this.context;
    const x9=c.x9;  // x9 = x10(=[x7+0xe0]) + opaque
    // The table entry addr = x9 + op*8. Dump 512 bytes from x9.
    send({t:'D2',base:base.toString(16),x9:x9.toString(16),x9_off:x9.sub(base).toString(16),
      tbl_from_x9:rp(x9,512)});
  }});
  send({t:'info',msg:'dump2 INSTALLED'});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

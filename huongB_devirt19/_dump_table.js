'use strict';
const SO='libmetasec_ov.so';
let installed=false, done=false;
function ru64(p){try{if(p.isNull())return'NULL';return p.readU64().toString(16).padStart(16,'0');}catch(e){return'ERR';}}
function rp(p,n){try{if(p.isNull())return'NULL';const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function install(base){
  if(installed)return; installed=true;
  Interceptor.attach(base.add(0x55950),{onEnter(){
    if(done)return; done=true;
    const c=this.context;
    const fp=c.fp, x7=c.x7;
    const pred=ru64(fp.sub(0x58));
    const htblptr=x7.add(0xe0).readU64();  // runtime handler table pointer
    // dump handler table region (64 entries * 8 = 512 bytes around it, plus a wider grab)
    const tbl=rp(ptr(htblptr),512);
    send({t:'DUMP',base:base.toString(16),pred_fp58:pred,htblptr:htblptr.toString(16),
      x7:x7.toString(16),table512:tbl});
  }});
  send({t:'info',msg:'dump table INSTALLED base='+base});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

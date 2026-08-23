'use strict';
// Hook the .msp state-file loader (0x12f278) to catch the decrypted PSK plaintext.
// Also hook AES round fn 0x159618 and generic read paths.
const SO='libmetasec_ov.so';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.';return s;}catch(e){return'ERR';}}

function inst(base){
  if(installed)return;installed=true;
  // Hook the loader function — capture args (x0/x1) and the buffer it returns
  Interceptor.attach(base.add(0x12f278),{
    onEnter(){ const c=this.context; this.x0=c.x0; this.x1=c.x1;
      // x1 may be the filename/suffix string
      let a='';try{a=this.x1.readCString();}catch(e){}
      this.arg1str=a;
    },
    onLeave(ret){
      // ret / x0 may point to a std::string or buffer with plaintext
      send({t:'LOADER',arg1:this.arg1str, ret:ret.toString(16),
        ret_bytes: hx(ret,64), ret_ascii: asc(ret,64)});
    }
  });
  send({t:'info',msg:'psk decrypt hook installed base='+base});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

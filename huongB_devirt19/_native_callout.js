// _native_callout.js — capture the 2 native call-out methods F depends on.
// Hook blr sites 0x13b010 (method=[[x0]+0x30]) and 0x13b034 (method=[[x0]+0x20]).
// Report: method address x8, resolved module+offset, this-ptr x0, vtable, args.
'use strict';
const SO='libmetasec_ov.so';
const SITES={ '0x13b010':'m30', '0x13b034':'m20' };
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rd(p,n){try{return hx(ptr(p).readByteArray(n));}catch(e){return null;}}
function resolve(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return {mod:m.name, off:'0x'+a.sub(m.base).toString(16)}; }catch(e){}
  return {mod:'?', off:a.toString()};
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; let seen={};
  Object.keys(SITES).forEach(off=>{
    const tag=SITES[off];
    Interceptor.attach(base.add(parseInt(off,16)),{onEnter(){
      if(seen[tag]&&seen[tag]>=2) return;
      seen[tag]=(seen[tag]||0)+1;
      const c=this.context; const x8=c.x8, x0=c.x0;
      const r=resolve(x8);
      let vt=null,vtres=null;
      try{ vt=x0.readPointer(); vtres=resolve(vt); }catch(e){}
      send({t:'callout', site:off, tag:tag, hit:seen[tag],
            method:x8.toString(), method_mod:r.mod, method_off:r.off,
            this_ptr:x0.toString(), this_data:rd(x0,64),
            vtable:vt?vt.toString():null, vtable_mod:vtres?vtres.mod:null,
            x1:c.x1.toString(), x2:c.x2.toString(), x1_data:rd(c.x1,48) });
    }});
  });
  send({t:'info',msg:'native-callout installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

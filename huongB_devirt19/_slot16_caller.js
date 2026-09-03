'use strict';
// Hook 0x150348 but ONLY when called from the slot16 closure path (LR near 0x9bf9c / 0x1503a8).
// At that point x1 = the actual slot16 string. Dump caller's registers/stack for the PSK source.
const SO='libmetasec_ov.so';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function readSSO(p){ // libc++ std::string
  try{ const b0=p.readU8();
    if((b0&1)===0){ const len=b0>>1; return {mode:'s',len:len,hex:hx(p.add(1),Math.min(len,23))}; }
    else{ const len=p.add(8).readU64().toInt32(); const d=p.add(16).readPointer(); return {mode:'l',len:len,hex:hx(d,Math.min(len,64))}; }
  }catch(e){return {err:''+e};}
}
function inst(base){
  if(installed)return;installed=true;
  let n=0;
  Interceptor.attach(base.add(0x150348),{
    onEnter(){
      const c=this.context;
      const lr=c.lr.sub(base).toInt32()>>>0;
      // slot16 path: caller inside closure invoker region 0x9bf00-0x9c600
      if(!(lr>=0x9bf00 && lr<=0x9c600))return;
      if(n>=20)return; n++;
      const s0=readSSO(c.x0), s1=readSSO(c.x1);
      // dump caller stack (PSK-derived state may be on stack) and x19-x28
      const regs={};for(let i=19;i<=28;i++){try{regs['x'+i]=c['x'+i].toString(16);}catch(e){}}
      send({t:'S16',n:n,lr:'0x'+lr.toString(16),str0:s0,str1:s1,regs:regs,
        stack:hx(c.sp,128)});
    }
  });
  send({t:'info',msg:'slot16 caller hook installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

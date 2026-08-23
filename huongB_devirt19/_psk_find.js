'use strict';
// PSK is a session-constant 16-32B binary buffer used to derive slot16.
// Hook the slot16 concat (0x150348) — at that point PSK-derived state is live.
// Dump the closure struct + surrounding memory to find the constant PSK buffer.
const SO='libmetasec_ov.so';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function inst(base){
  if(installed)return;installed=true;
  let n=0;
  // Hook concat 0x150348: x0=query str, x1=slot16 str. Dump both + their backing.
  Interceptor.attach(base.add(0x150348),{
    onEnter(){
      if(n>=25)return; n++;
      const c=this.context;
      // x1 = slot16 std::string (SSO inline). Read it.
      // libc++ string: if (byte0 & 1)==0 short mode: len=byte0>>1, data at +1
      let slot16='';
      try{
        const b0=c.x1.readU8();
        if((b0&1)===0){ const len=b0>>1; slot16=hx(c.x1.add(1),Math.min(len,23)); }
        else { const dat=c.x1.add(16).readPointer(); slot16=hx(dat,16); }
      }catch(e){}
      // Dump caller context registers x19-x28 (may hold PSK ptr) + stack
      const regs={};
      for(let i=19;i<=28;i++){try{regs['x'+i]=c['x'+i].toString(16);}catch(e){}}
      send({t:'CONCAT',n:n,slot16:slot16,regs:regs,
        x0_deref:hx(c.x0,32), x1_deref:hx(c.x1,32)});
    }
  });
  send({t:'info',msg:'psk find installed base='+base});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

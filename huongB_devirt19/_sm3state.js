'use strict';
const SO='libmetasec_ov.so';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function inst(base){
  if(installed)return;installed=true;
  let n=0;
  const states={};
  Interceptor.attach(base.add(0xa0748),{onEnter(){
    n++;
    const c=this.context;
    const st=hx(c.x0.add(8),32);
    states[st]=(states[st]||0)+1;
  }});
  setInterval(function(){
    // report the most common initial states
    const sorted=Object.keys(states).sort((a,b)=>states[b]-states[a]).slice(0,6);
    const top={};for(const s of sorted)top[s]=states[s];
    send({t:'ST',total:n,top:top});
  },3000);
  send({t:'info',msg:'sm3 state installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

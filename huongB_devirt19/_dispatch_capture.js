'use strict';
const SO='libmetasec_ov.so';
let installed=false;
const targets={}; // handler_offset -> count
const opTarget={}; // opcode -> handler_offset

function install(base){
  if(installed)return; installed=true;
  const baseVal = base;
  // Hook br x15 at 0x55930 — capture x15 (handler target) and x8 (opcode word)
  Interceptor.attach(base.add(0x55930),{onEnter(){
    const c=this.context;
    const x15=c.x15;
    // handler offset relative to module base
    const off = x15.sub(baseVal);
    const offNum = off.toInt32() >>> 0;
    const key = '0x'+offNum.toString(16);
    targets[key]=(targets[key]||0)+1;
  }});
  setInterval(function(){
    // report top targets
    const sorted=Object.keys(targets).sort((a,b)=>targets[b]-targets[a]);
    const top={};
    for(let i=0;i<Math.min(20,sorted.length);i++) top[sorted[i]]=targets[sorted[i]];
    send({t:'DISPATCH',uniq:sorted.length,top:top});
  },2000);
  send({t:'info',msg:'dispatch capture INSTALLED base='+base});
}

const m=Process.findModuleByName(SO);
if(m) install(m.base);
else {
  const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});
  send({t:'info',msg:'waiting dlopen'});
}

'use strict';
const SO='libmetasec_ov.so';
let installed=false,cnt=0;
function install(base){
  if(installed)return;installed=true;
  Interceptor.attach(base.add(0x55930),{onEnter(){   // br x15
    if(cnt>=8)return;cnt++;
    const c=this.context;
    const x15=c.x15, x8=c.x8, x9=c.x9;
    send({t:'X15',n:cnt,base:base.toString(16),
      x15:x15.toString(16),x15_off:x15.sub(base).toString(16),
      x8:x8.toString(16),x9:x9.toString(16)});
  }});
  send({t:'info',msg:'x15 dump installed'});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

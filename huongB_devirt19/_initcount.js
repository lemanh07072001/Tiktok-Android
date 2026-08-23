'use strict';
const SO='libmetasec_ov.so';
let installed=false;
const cnt={sm3:0,md5:0,md5_finalize:0,vm:0};
function inst(base){
  if(installed)return;installed=true;
  Interceptor.attach(base.add(0xa0748),{onEnter(){cnt.sm3++;}});
  Interceptor.attach(base.add(0x15b594),{onEnter(){cnt.md5++;}});
  Interceptor.attach(base.add(0x15b43c),{onEnter(){cnt.md5_finalize++;}});
  Interceptor.attach(base.add(0x55950),{onEnter(){cnt.vm++;}});
  setInterval(function(){send({t:'C',cnt:cnt});},2000);
  send({t:'info',msg:'initcount installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

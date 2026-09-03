'use strict';
const SO='libmetasec_ov.so';
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; let vmN=0, f4N=0, lrHit=0;
  Interceptor.attach(base.add(0x52924),{onEnter(){ vmN++;
    const off=this.context.lr.sub(base).toString(16);
    if(off==='1384e8'){ lrHit++; if(lrHit<=3) send({t:'info',msg:'VM entry with LR=0x1384e8 (#'+lrHit+')'}); }
  }});
  Interceptor.attach(base.add(0x1384e4),{onEnter(){ f4N++; if(f4N<=3) send({t:'info',msg:'*** 0x1384e4 BL fired #'+f4N+' x1='+this.context.x1}); }});
  setTimeout(function(){ send({t:'info',msg:'STATS vmEntries='+vmN+' LR=1384e8 hits='+lrHit+' 0x1384e4 fired='+f4N}); }, 40000);
  send({t:'info',msg:'dbg installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

'use strict';
const SO='libmetasec_ov.so';
let installed=false;
const events=[];
let prev=null;
function install(base){
  if(installed)return;installed=true;
  const modBase=base;
  Interceptor.attach(base.add(0x55950),{onEnter(){
    if(events.length>=1500)return;
    const c=this.context;
    try{
      const bcp=c.x23.readPointer();
      const off=bcp.sub(modBase).toInt32()>>>0;
      const w=bcp.add(4).readU32();
      // snapshot regfile (32 x u64) as low-32 hex for compactness
      const x24=c.x24;
      const rf=[];
      for(let i=0;i<32;i++){ rf.push(x24.add(i*8).readU64().toString()); }
      // record: this opcode's word/off, and regfile state BEFORE it runs
      // The diff vs previous snapshot shows what the PREVIOUS opcode did.
      if(prev){
        // compute which regfile slots changed
        const changed=[];
        for(let i=0;i<32;i++){ if(prev.rf[i]!==rf[i]) changed.push([i,prev.rf[i],rf[i]]); }
        events.push({op:prev.op,off:prev.off,w:prev.w,changed:changed});
      }
      prev={op:w&0x3f,off:off,w:w,rf:rf};
    }catch(e){}
  }});
  setInterval(function(){
    if(events.length>0){send({t:'OPSEM',samples:events.slice(0,1500)});events.length=0;}
  },1500);
  send({t:'info',msg:'opsem installed'});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

'use strict';
const SO='libmetasec_ov.so';
let installed=false;
const execOffs=[];  // list of bytecode va offsets actually dispatched
function install(base){
  if(installed)return;installed=true;
  const modBase=base;
  Interceptor.attach(base.add(0x55950),{onEnter(){
    if(execOffs.length>=4000)return;
    const c=this.context;
    try{
      const bcp=c.x23.readPointer();  // current bytecode ptr
      const off=bcp.sub(modBase).toInt32()>>>0;
      // read the opcode word at bcp+4 (dispatch does x8=*x23; x8+=4; w8=*x8)
      const w=bcp.add(4).readU32();
      execOffs.push([off,w]);
    }catch(e){}
  }});
  setInterval(function(){
    if(execOffs.length>0){
      send({t:'TRACE',count:execOffs.length,samples:execOffs.slice(0,4000)});
      execOffs.length=0;
    }
  },1500);
  send({t:'info',msg:'exec trace installed base='+base});
}
const m=Process.findModuleByName(SO);
if(m)install(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)install(mm.base);}}});}

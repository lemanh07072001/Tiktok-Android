'use strict';
const SO='libmetasec_ov.so';
const SM3=0xa0748;
function inst(base){
  Interceptor.attach(base.add(SM3),{
    onEnter(){
      try{
        const blk=this.context.x1;
        if(blk.isNull())return;
        const b=new Uint8Array(blk.readByteArray(64));
        let match=true;
        for(let i=0;i<28;i++){if(b[i]!==b[36+i]){match=false;break;}}
        if(!match)return;
        let psk='',rb='';
        for(let i=0;i<32;i++)psk+=('0'+b[i].toString(16)).slice(-2);
        for(let i=32;i<36;i++)rb+=('0'+b[i].toString(16)).slice(-2);
        send({t:'PSK',psk:psk,rb:rb,time:Date.now()});
      }catch(e){}
    }
  });
  send({t:'info',msg:'SM3 simon_key hook armed @'+base.add(SM3)});
}
const m=Process.findModuleByName(SO);
if(m) inst(m.base);
else { const dl=Module.findGlobalExportByName('dlopen')||Module.findGlobalExportByName('android_dlopen_ext');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}}); }

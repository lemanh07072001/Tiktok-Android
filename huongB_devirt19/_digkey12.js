'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null,lo=null,hi=null,active=0,inv=0,cap=0;
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;
  base=m.base;lo=base;hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){const sel=u32(this.context.x1);if(sel!==369)return;if(active)return;active=1;inv++;this.mine=1;},
    onLeave(r){if(!this.mine)return;active=0;send({t:'PROD_DONE',inv:inv});}
  });
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(!active)return; if(cap>120)return; cap++;
      const len=u32(this.context.x1);
      const rl=Math.min(len,2048);
      send({t:'D',inv:inv,len:len,x2:u32(this.context.x2),
            msg:h(this.context.x0,rl), out:len<=16?h(this.context.x0,16):null});
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',active:active,inv:inv,cap:cap}),3000);

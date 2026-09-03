'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null,lo=null,hi=null,active=0,inv=0,capd=0,seq=0;
let x2seen={};
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;
  base=m.base;lo=base;hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){const sel=u32(this.context.x1);if(sel!==369)return;if(capd)return;
      active=1;inv++;this.mine=1;seq=0;x2seen={};
      send({t:'PE',inv:inv,x0ctx:h(this.context.x0,0x60)});
    },
    onLeave(r){if(!this.mine)return;active=0;capd=1;send({t:'PD',inv:inv});}
  });
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(!active)return;
      const x2=this.context.x2; const x2s=x2.toString();
      let x2mem=null;
      if(!x2seen[x2s]){x2seen[x2s]=1; x2mem=h(x2,192);}
      send({t:'D',inv:inv,seq:seq++,len:u32(this.context.x1),x2:x2s,
            x0m:h(this.context.x0,80), x2mem:x2mem});
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',capd:capd}),3000);

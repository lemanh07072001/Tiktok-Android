'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null,active=0,inv=0,capd=0,seq=0;
const MAXINV=4;
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function derefdump(p){ // dump 8 pointers from struct, deref each 64B
  const out={};
  try{
    for(let i=0;i<8;i++){
      try{const q=p.add(i*8).readPointer(); out['p'+(i*8).toString(16)]=q.toString();
          out['d'+(i*8).toString(16)]=h(q,64);}catch(e){out['p'+(i*8).toString(16)]='ERR';}
    }
  }catch(e){}
  return out;
}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){const sel=u32(this.context.x1);if(sel!==369)return;if(inv>=MAXINV)return;
      active=1;inv++;this.mine=1;seq=0;},
    onLeave(r){if(!this.mine)return;active=0;if(inv>=MAXINV)capd=1;}
  });
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(!active)return;
      const len=u32(this.context.x1);
      const rl=Math.min(len,1600);
      const rec={t:'D',inv:inv,seq:seq++,len:len,x2:this.context.x2.toString(),
                 msg:h(this.context.x0,rl)};
      if(seq===1) rec.ctx=derefdump(this.context.x2); // struct deref on first call
      send(rec);
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',capd:capd,inv:inv}),3000);

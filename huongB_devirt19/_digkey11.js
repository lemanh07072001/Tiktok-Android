'use strict';
const SO='libmetasec_ov.so';
const PROD=0x879d8;      // producer f(ctx,sel)
const COMPRESS=0xa0748;  // SM3 compression (verified pure-Node in memory)
const DRV=0x9fdac;       // hash driver
let base=null,lo=null,hi=null,active=0,invno=0;
function off(p){try{if(p.compare(lo)>=0&&p.compare(hi)<0)return p.sub(base).toInt32();}catch(e){}return -1;}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function readStd(p){ // libc++ std::string at ptr p
  try{const f=p.readU8();
    if(f&1){const size=p.add(8).readU64().toNumber();const dp=p.add(16).readPointer();return {m:'L',n:size,s:h(dp,Math.min(size,64)),asc:dp.readUtf8String(Math.min(size,64))};}
    else{const size=f>>1;return {m:'S',n:size,s:h(p.add(1),Math.min(size,23)),asc:p.add(1).readUtf8String(Math.min(size,23))};}
  }catch(e){return {err:''+e};}
}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;
  base=m.base;lo=base;hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){const sel=u32(this.context.x1);if(sel!==369)return;
      if(active)return; active=1; invno++; this.mine=1; this.x8=this.context.x8;
      const x0=this.context.x0;
      send({t:'PROD_ENTER',inv:invno,ctx:h(x0,0x120),x8:this.x8?this.x8.toString():null,
            sec: (function(){try{return x0.add(0x10).readPointer().readUtf8String(120);}catch(e){return null;}})()});
    },
    onLeave(r){ if(!this.mine)return;
      const dig=readStd(this.context.x0);
      let dig8=null; try{dig8=readStd(this.x8);}catch(e){}
      send({t:'PROD_LEAVE',inv:invno,ret_x0:dig,ret_x8:dig8});
      active=0;
    }
  });
  // compression: capture state(x0,32B) + block(x1,64B) while producer active
  let bn=0;
  Interceptor.attach(base.add(COMPRESS),{
    onEnter(a){ if(!active)return; if(bn>200)return; bn++;
      send({t:'BLK',inv:invno,st:this.context.x0.toString(),block:h(this.context.x1,64)});
    }
  });
  // driver bounds
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(!active)return;
      send({t:'DRV',inv:invno,x0:this.context.x0.toString(),x1:u32(this.context.x1),x2:u32(this.context.x2),
            x0mem:h(this.context.x0,32),x1mem:h(this.context.x1,64)});
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',active:active,inv:invno}),3000);

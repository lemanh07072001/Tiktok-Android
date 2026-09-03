'use strict';
// DECISIVE probe: is the len=16 DRV call a WRITE (finalize->x0) or READ (feed secret from x0)?
// Compare x0 contents at onEnter vs onLeave for every DRV call in a producer(369) window.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null, active=0, inv=0, seq=0; const MAXINV=3;
function u32(r){try{return parseInt(r.toString())>>>0;}catch(e){return -1;}}
function h(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function install(){
  const m=Process.findModuleByName(SO);if(!m)return false;base=m.base;
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){const sel=u32(this.context.x1); if(sel!==369)return; if(inv>=MAXINV)return; active=1; inv++; this.mine=1; seq=0;
      send({t:'PROD_ENTER',inv:inv});},
    onLeave(r){if(this.mine){active=0; send({t:'PROD_LEAVE',inv:inv});}}
  });
  Interceptor.attach(base.add(DRV),{
    onEnter(a){ if(!active)return; const len=u32(this.context.x1); this._len=len; this._x0=this.context.x0; this._x2=this.context.x2.toString();
      this._seq=seq++; this._before= (len<=64)? h(this.context.x0,Math.max(16,Math.min(len,64))) : ('len='+len+' msg='+h(this.context.x0,32));
      // capture message content for update-sized calls
      this._msg = (len>16 && len<=2048)? h(this.context.x0, Math.min(len,1600)) : null;
    },
    onLeave(r){ if(!active && this._seq===undefined)return; if(this._x0===undefined)return;
      const after=(this._len<=64)? h(this._x0,Math.max(16,Math.min(this._len,64))) : h(this._x0,32);
      const changed = (this._before!==after);
      send({t:'DRV',inv:inv,seq:this._seq,len:this._len,x2:this._x2,
            before:this._before, after:after, changed:changed, msg:this._msg});
      this._x0=undefined;this._seq=undefined;
    }
  });
  send({t:'ready'});return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',inv:inv}),4000);

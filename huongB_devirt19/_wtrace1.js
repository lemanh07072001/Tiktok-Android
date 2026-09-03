'use strict';
// _wtrace1.js — characterize producer 0x879d8(ctx, sel=0x171):
//   GETTER (reads cached slot16 from ctx) vs COMPUTER (derives on the fly)
// Capture producer IN/OUT + correlate with DRV feed by value. Read-only, spawn.
const SO='libmetasec_ov.so';
const PROD=0x879d8, DRV=0x9fdac;
let base=null,lo=null,hi=null;
let nProd=0, nFeed=0; const MAXP=8, MAXF=8;

function off(p){ try{ if(p.compare(lo)>=0&&p.compare(hi)<0) return '+0x'+p.sub(base).toString(16);}catch(e){} return ''+p; }
function h(p,n){ try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString(),size:m.size});

  Interceptor.attach(base.add(PROD),{
    onEnter(a){
      let sel; try{ sel=this.context.x1.toInt32()&0xffffffff; }catch(e){ return; }
      if(sel!==0x171) return;
      this._is=1;
      this._x0=this.context.x0;   // ctx
      this._x8=this.context.x8;   // AArch64 indirect-result ptr (struct>16B return)
      if(nProd<MAXP){
        send({t:'PROD_IN', x0:''+this.context.x0, x2:''+this.context.x2,
              x8:''+this.context.x8, lr:off(this.context.lr),
              ctx64:h(this.context.x0,64),
              x8pre: (this.context.x8.compare(ptr(0))>0)? h(this.context.x8,16):'nullx8'});
      }
    },
    onLeave(r){
      if(this._is!==1) return;
      if(nProd<MAXP){
        nProd++;
        // slot16 could come back in: x0:x1 pair (16B), or via [x8]
        let x0pair=null, x8out=null;
        try{ x0pair=h(this.context.x0,16); }catch(e){}
        try{ if(this._x8.compare(ptr(0))>0) x8out=h(this._x8,16); }catch(e){}
        send({t:'PROD_OUT', ret:''+r, ret16:h(r,16),
              x0_x1pair:x0pair, x8out:x8out,
              ctx64_after:h(this._x0,64)});
      }
    }
  });

  Interceptor.attach(base.add(DRV),{
    onEnter(a){
      let len; try{ len=this.context.x1.toInt32()&0xffffffff; }catch(e){ return; }
      if(len!==16) return;
      const x0=this.context.x0; const val=h(x0,16);
      if(/^0+$/.test(val)) return;
      if(nFeed>=MAXF) return; nFeed++;
      let bt=[];
      try{ bt=Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,8).map(off); }
      catch(e){ try{ bt=Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,8).map(off);}catch(e2){bt=['bterr'];} }
      send({t:'FEED', slot16:val, x0:''+x0, stack:bt});
    }
  });

  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const ti=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(ti,150);}; setTimeout(ti,300); }
setInterval(()=>send({t:'mon',nProd:nProd,nFeed:nFeed}),5000);

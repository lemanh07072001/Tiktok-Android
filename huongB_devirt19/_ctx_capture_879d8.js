'use strict';
/* Option A: live-min ctx capture at producer 0x879d8 (selector w1=0x171).
 * onEnter: dump x0[0..0x100] (ctx struct) + x1/x2/x3/x8 + lr.
 * onLeave: capture candidate slot16 outputs (x0:x1 inline, *x0, *x8, ctx-after).
 * ATTACH mode, read-only, no patch. Filter w1==0x171. Cap MAX captures.
 */
const SO='libmetasec_ov.so';
const OFF=0x879d8;
const SEL=0x171;
const MAX=10;
let base=null, lo=null, hi=null, n=0;

function inSelf(p){try{return p.compare(lo)>=0&&p.compare(hi)<0;}catch(e){return false;}}
function off(p){try{if(inSelf(p))return '0x'+p.sub(base).toString(16);}catch(e){}return null;}
function hx(ab){if(!ab)return null;const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function dump(p,len){try{if(p.isNull())return null;return hx(p.readByteArray(len));}catch(e){return null;}}

function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',msg:'libmetasec loaded',base:base.toString(),size:m.size});
  Interceptor.attach(base.add(OFF),{
    onEnter(a){
      if(n>=MAX)return;
      const c=this.context;
      let w1; try{w1=c.x1.toUInt32()>>>0;}catch(e){w1=-1;}
      if(w1!==SEL){this._skip=true;return;}
      this._skip=false;
      this._x0=c.x0; this._x8=c.x8;
      this._e={
        w1:'0x'+w1.toString(16),
        x0:c.x0.toString(), x1:c.x1.toString(), x2:c.x2.toString(), x3:c.x3.toString(), x8:c.x8.toString(),
        lr:off(c.lr), lrabs:c.lr.toString(),
        ctx256:dump(c.x0,0x100),
        x2blob:dump(c.x2,64),
        x3blob:dump(c.x3,64),
      };
    },
    onLeave(ret){
      if(n>=MAX||this._skip)return;
      const c=this.context;
      n++;
      send(Object.assign({t:'CTX',seq:n},this._e,{
        retx0:c.x0.toString(), retx1:c.x1.toString(),
        outAtX0:dump(c.x0,16),
        outAtX8:this._x8?dump(this._x8,16):null,
        ctx256_after:this._x0?dump(this._x0,0x100):null,
      }));
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,200);}; setTimeout(f,300); }
setInterval(()=>send({t:'mon',n:n}),4000);

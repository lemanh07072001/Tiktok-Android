'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const A_HEX='c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163';
let base=null, done=false;
function hexOf(p,n){ try{ const b=new Uint8Array(p.readByteArray(n)); let s='';
  for(let i=0;i<n;i++)s+=('0'+b[i].toString(16)).slice(-2); return s; }catch(e){return null;} }
function resolve(addr){
  try{ const m=Process.findModuleByAddress(addr);
    if(m) return m.name.replace('.so','')+'+0x'+addr.sub(m.base).toString(16);
    return addr.toString(); }catch(e){ return '?'; }
}
// manual arm64 frame-pointer unwind — no Frida Backtracer (stealth)
function fpwalk(ctx){
  const out=[]; 
  out.push('LR='+resolve(ctx.lr));
  try{ let fp=ctx.fp;
    for(let i=0;i<16;i++){
      if(fp.isNull())break;
      const savedFp=fp.readPointer();
      const savedLr=fp.add(8).readPointer();
      if(savedLr.isNull())break;
      out.push(resolve(savedLr));
      if(savedFp.compare(fp)<=0)break; // stack grows down; must ascend
      fp=savedFp;
    }
  }catch(e){ out.push('walk_err:'+e); }
  return out;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(DRV),{ onEnter(a){
    if(done)return;
    const len=this.context.x1.toInt32()&0xffffffff;
    if(len<68)return;
    if(hexOf(this.context.x0,32)!==A_HEX)return;
    done=true;
    send({t:'BT', len:len, x0:this.context.x0.toString(), chain:fpwalk(this.context)});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO))install();
else { const t=()=>{ if(Process.findModuleByName(SO))install(); else setTimeout(t,200); }; setTimeout(t,400); }
setInterval(()=>send({t:'mon',done:done}),5000);

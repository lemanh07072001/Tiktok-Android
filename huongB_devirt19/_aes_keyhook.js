'use strict';
const SO='libmetasec_ov.so';
const KEXP=0x1591bc;          // aes_set_encrypt_key(AES_KEY* x0, u8* userKey x1, int keybytes w2)
let base=null;
function hexbuf(p,n){ try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return '<err>';} }
function selfOff(p){ try{ if(p.compare(base)>=0){const o=p.sub(base).toInt32(); if(o>=0&&o<0x400000) return o;} }catch(e){} return -1; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; send({t:'info',msg:'metasec base',base:base.toString()});
  Interceptor.attach(base.add(KEXP),{
    onEnter(a){
      const ctx=this.context;
      let klen=0; try{ klen=parseInt(ctx.x2.toString())&0xffffffff; }catch(e){}
      let nb=(klen===16||klen===24||klen===32)?klen:32;
      send({t:'KEXP', klen:klen, key:hexbuf(ctx.x1,nb), lr:selfOff(ctx.lr), x0:(ctx.x0?ctx.x0.toString():null)});
    }
  });
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else { const f=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(f,200);}; setTimeout(f,300); }
setInterval(()=>send({t:'mon'}),5000);

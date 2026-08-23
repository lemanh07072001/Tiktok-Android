'use strict';
// _psk_live.js — proven SM3-chain slot16 capture (from slot16_capture.js) PLUS
// PSK genesis hook (msp_loader 0x12f278, x0=sret std::string plaintext).
const SO='libmetasec_ov.so';
const SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function asc(u,a,b){let s='';for(let i=a;i<b;i++)s+=String.fromCharCode(u[i]);return s;}
function hxp(p,n){try{return hx(p.readByteArray(n));}catch(e){return'ERR';}}
function ascp(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.';return s;}catch(e){return'ERR';}}
function readStr(p){try{const b0=p.readU8();if((b0&1)===0){const len=b0>>1;return{len,mode:'s',hex:hxp(p.add(1),Math.min(len,22)),ascii:ascp(p.add(1),Math.min(len,22))};}else{const len=p.add(8).readU64().toNumber();const d=p.add(16).readPointer();return{len,mode:'l',hex:hxp(d,Math.min(len,256)),ascii:ascp(d,Math.min(len,256))};}}catch(e){return{err:String(e)};}}

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const chain={};
  // PSK genesis
  Interceptor.attach(base.add(0x12f278),{
    onEnter(){const c=this.context;this.out=c.x0;this.fn=readStr(c.x1);},
    onLeave(){send({t:'PSK_GENESIS',file:this.fn,plaintext:readStr(this.out)});}
  });
  // proven slot16 via SM3 chain
  Interceptor.attach(base.add(SM3),{
    onEnter(){const tid=this.threadId;let st,inp;
      try{st=hx(this.context.x0.add(8).readByteArray(32));inp=new Uint8Array(this.context.x1.readByteArray(64));}catch(e){return;}
      if(st===IV_LE)chain[tid]=Array.from(inp);
      else if(chain[tid]){for(let i=0;i<64;i++)chain[tid].push(inp[i]);}
      else return;
      const a=chain[tid],L=a.length;if(L<9)return;
      let bl=0;for(let i=L-8;i<L;i++)bl=bl*256+a[i];const mlen=bl/8;
      if(!(mlen>16&&mlen<L)||a[mlen]!==0x80)return;
      if(a[mlen-1]!==0x30||mlen<200){delete chain[tid];return;}
      const full=asc(a,0,mlen);
      if(full.indexOf('device_platform=')<0||full.indexOf('&device_id=')<0){delete chain[tid];return;}
      let slot='';for(let i=mlen-17;i<mlen-1;i++)slot+=('0'+a[i].toString(16)).slice(-2);
      send({t:'obs',ts_wall:Date.now(),slot16:slot,query:full.slice(0,mlen-17)});
      delete chain[tid];
    }
  });
  send({t:'info',msg:'psk_live installed base='+base});
  return true;
}
if(Process.findModuleByName(SO))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{
  onEnter(a){try{this.p=a[0].readCString();}catch(e){}},
  onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}
});

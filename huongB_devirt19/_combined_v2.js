'use strict';
// Combined v2: decoder 0x891f4 (token) + MD5 one-shot 0x15b594 (preimage + 16B output).
// Decisive test: does any MD5 output == a recurring device-stable decoder token?
//   (recurring: 46c03b52.., 6c109094.., f3136184..)  If yes -> hexstr32 = MD5(preimage).
const SO='libmetasec_ov.so';
const DEC=0x891f4, MD5=0x15b594;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function asc(u,a,b){let s='';for(let i=a;i<b;i++)s+=String.fromCharCode(u[i]);return s;}
let base=null,decSeq=0,md5Seq=0;
const TARGETS=new Set(['46c03b52742b3f2615a3abdf1636b754','6c109094bc9ab89e050fbd3e2ca6b99e','f31361844bd2a9dfda8e7ff7edc91ce0']);
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base;
  // decoder
  Interceptor.attach(base.add(DEC),{
    onEnter(){const c=this.context; try{this._x8=c.x8;this._x0=c.x0;this._inlen=ptr(c.x0).add(4).readU32();}catch(e){this._x8=null;}},
    onLeave(){ if(!this._x8)return; try{
      const outlen=ptr(this._x8).add(4).readU32(); if(outlen!==16)return;
      const dptr=ptr(this._x8).add(8).readPointer(); const slot16=hx(dptr,16);
      let in_ascii=null; try{const ip=ptr(this._x0).add(8).readPointer(); in_ascii=asc(new Uint8Array(ip.readByteArray(this._inlen)),0,this._inlen);}catch(e){}
      send({t:'DEC',seq:decSeq++,tid:this.threadId,ts:Date.now(),in_ascii:in_ascii,slot16:slot16});
    }catch(e){} }
  });
  // MD5 one-shot: capture inputs (both sig interpretations) + outputs (x0/x2 @leave)
  Interceptor.attach(base.add(MD5),{
    onEnter(){const c=this.context; this._x0=c.x0;this._x1=c.x1;this._x2=c.x2;
      // dump candidate preimages: (data=x0,len=x1) and (data=x1,len=x2)
      let inA=null,inB=null;
      try{const n=c.x1.toInt32(); if(n>0&&n<1024) inA=hx(c.x0,n);}catch(e){}
      try{const n=c.x2.toInt32(); if(n>0&&n<1024) inB=hx(c.x1,n);}catch(e){}
      this._inA=inA; this._inB=inB;
    },
    onLeave(){ try{
      const o0=hx(this._x0,16), o2=hx(this._x2,16);
      // only emit if an output looks like a target OR always (cap volume)
      const isHit = TARGETS.has(o0)||TARGETS.has(o2);
      if(md5Seq<80 || isHit){
        send({t:'MD5',seq:md5Seq++,tid:this.threadId,ts:Date.now(),
              out_x0:o0,out_x2:o2,in_dataX0:this._inA,in_dataX1:this._inB,hit:isHit});
      }
    }catch(e){} }
  });
  send({t:'info',msg:'combined v2 installed base='+base});
  return true;
}
setInterval(()=>send({t:'mon',d:decSeq,m:md5Seq}),5000);
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{
  onEnter(a){try{this.p=a[0].readCString();}catch(e){}},
  onLeave(){ if(this.p&&this.p.indexOf(SO)>=0) install(); }
});

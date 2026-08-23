'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
if(!m){send({t:'err',msg:'no metasec'});}
else{
const base=m.base;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function readStr(p){ // std::string: could be SSO or heap. try read ptr+len layout
  try{
    // libc++ std::string: [0]=cap/flag,[8]=size,[16]=data ptr (long mode) OR inline (short mode)
    const first=p.readU8();
    if(first&1){ // long mode
      const size=p.add(8).readU64().toInt32();
      const dat=p.add(16).readPointer();
      return {mode:'long',size:size,hex:hx(dat,Math.min(size,64))};
    }else{ // short mode: size in first byte>>1, data inline at +1
      const size=first>>1;
      return {mode:'short',size:size,hex:hx(p.add(1),Math.min(size,23))};
    }
  }catch(e){return {err:e.message};}
}

// Hook the closure invoker at 0x9bf88 — note 33: x0 = closure struct
// { [0]=concat fn 0x150348, [0x10]=query str ptr, [0x18]=slot16 str ptr }
let hits=0;
Interceptor.attach(base.add(0x9bf88),{onEnter(){
  if(hits>=8)return;
  const c=this.context;
  const x0=c.x0;
  try{
    const target=x0.readPointer().sub(base);   // [0] = bound fn
    if(target.toInt32()===0x150348){
      hits++;
      const queryPtr=x0.add(0x10).readPointer();
      const slotPtr=x0.add(0x18).readPointer();
      send({t:'CLOSURE',n:hits,
        query:readStr(queryPtr),
        slot16:readStr(slotPtr),
        struct:hx(x0,0x40)});
    }
  }catch(e){}
}});
send({t:'info',msg:'PSK runtime hook installed base='+base});
}

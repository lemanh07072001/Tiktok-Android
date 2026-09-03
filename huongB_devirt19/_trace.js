const m=Process.findModuleByName('libmetasec_ov.so'), base=m.base, end=base.add(m.size);
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
// libc++ std::string read: obj -> {size,dataPtr}
function rdstr(o){try{const f=o.readU8();let sz,dp;if(f&1){sz=o.add(8).readU64().toNumber();dp=o.add(16).readPointer();}else{sz=f>>1;dp=o.add(1);}if(sz<0||sz>4096)return null;return{sz:sz,dp:dp,hex:hx(dp,Math.min(sz,64))};}catch(e){return null;}}
function rel(p){if(p.compare(base)>=0&&p.compare(end)<0)return 'so+0x'+p.sub(base).toString(16);const mm=Process.findModuleByAddress(p);return mm?mm.name+'+0x'+p.sub(mm.base).toString(16):p.toString();}
let n=0;
Interceptor.attach(base.add(0x150348),{onEnter(){
  if(n>=4)return;
  const x0=this.context.x0,x1=this.context.x1;
  const q=rdstr(x0), s=rdstr(x1);
  // is x1 the 16-byte slot? check size 16 and preceded by query ending device_id
  if(!s||s.sz!==16) return;
  n++;
  const bt=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,6).map(rel);
  send({t:'C',qhead:q?String.fromCharCode.apply(null,new Uint8Array(q.dp.readByteArray(Math.min(q.sz,24)))):null,
        qlen:q?q.sz:0, slot16:s.hex, slotDataPtr:s.dp.toString(), slotDataRel:rel(s.dp),
        memAround:hx(s.dp.sub(16),48), bt:bt});
}});
send({t:'info',msg:'trace 0x150348 ready'});

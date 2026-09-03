// _slot16_writer.js — route S final capture: WHO produces the 16-byte slot16?
// Detect the "S-call" = 0xa0748 entry whose 64-byte block is a padded 16-byte message
//   (block[16]==0x80, tail bit-length==0x80/128) with NONZERO first 16 bytes = slot16.
// SAFE backtrace: NO Thread.backtrace (crashes under PAC) — instead manual stack scan,
//   reading 8-byte slots with try/catch and integer-comparing against libmetasec range.
// The nearest SELF return address (and LR) is the caller that assembled slot16.
// Single hook at ENTRY 0xa0748 only (see [[frida-x16-clobber-libmetasec]]).
'use strict';
const SO='libmetasec_ov.so';
const ENTRY=0xa0748;
let base=null, top=null, n=0, done=false; const MAX=12;
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,k){try{return hx(p.readByteArray(k));}catch(e){return null;}}
function inSelf(p){ // p is a NativePointer; true if base<=p<top (no deref)
  try{ return p.compare(base)>=0 && p.compare(top)<0; }catch(e){ return false; }
}
function selfOff(p){ return 'SELF+0x'+p.sub(base).toString(16); }
function isS(block){
  if(!block||block.length!==128) return false;
  if(block.substr(32,2)!=='80') return false;
  if(!block.endsWith('0000000000000080')) return false;
  for(let i=34;i<112;i+=2) if(block.substr(i,2)!=='00') return false;
  const slot=block.substr(0,32);
  return slot!=='00000000000000000000000000000000';
}
// manual stack walk: scan sp..sp+N for 8-byte values landing inside SO
function scanStack(sp){
  const found=[]; const WORDS=96;
  for(let i=0;i<WORDS;i++){
    let v; try{ v=sp.add(i*8).readPointer(); }catch(e){ break; }
    if(inSelf(v)) found.push({slot:i, off:selfOff(v)});
    if(found.length>=12) break;
  }
  return found;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; top=m.base.add(m.size);
  send({t:'info',base:base.toString(),size:m.size});
  Interceptor.attach(base.add(ENTRY),{onEnter(){
    if(done)return; const c=this.context; const block=rh(c.x1,64);
    if(!isS(block))return;
    n++;
    const lr=c.lr;
    send({t:'S',n,tid:this.threadId,slot16:block.substr(0,32),
          lr: inSelf(lr)?selfOff(lr):lr.toString(),
          sp: c.sp.toString(),
          stack_self: scanStack(c.sp)});
    if(n>=MAX){done=true;send({t:'stopped',total:n});}
  }});
  return true;
}
if(Process.findModuleByName(SO))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

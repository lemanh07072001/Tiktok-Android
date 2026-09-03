// _slot16_inputs.js — D1 (lift VM 0x55950): at each S-call (SM3 of a nonzero slot16),
// snapshot the producer's leftover state: all GPRs + a stack window + the buffer around x1.
// Producer just finished; its inputs (PSK-derived material, per-req nonce, ARX state) still
// live in registers/stack. Correlate offline: bytes CONSTANT across calls = device/PSK context;
// bytes that co-vary with slot16 = the ARX inputs. Interceptor@0xa0748 ENTRY proven safe (writer ran clean).
'use strict';
const SO='libmetasec_ov.so';
const ENTRY=0xa0748;
let base=null, top=null, n=0, done=false; const MAX=16;
const GPR=['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15',
           'x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','fp','lr','sp'];
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function rh(p,k){try{return hx(p.readByteArray(k));}catch(e){return null;}}
function selfOff(p){try{if(p.compare(base)>=0&&p.compare(top)<0)return'SELF+0x'+p.sub(base).toString(16);}catch(e){}return p?p.toString():null;}
function isS(block){
  if(!block||block.length!==128) return false;
  if(block.substr(32,2)!=='80') return false;
  if(!block.endsWith('0000000000000080')) return false;
  for(let i=34;i<112;i+=2) if(block.substr(i,2)!=='00') return false;
  return block.substr(0,32)!=='00000000000000000000000000000000';
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; top=m.base.add(m.size);
  send({t:'info',base:base.toString(),size:m.size});
  Interceptor.attach(base.add(ENTRY),{onEnter(){
    if(done)return; const c=this.context; const block=rh(c.x1,64);
    if(!isS(block))return;
    n++;
    const regs={}; for(const r of GPR){ try{ regs[r]=c[r].toString(); }catch(e){ regs[r]=null; } }
    // dump stack window [sp, sp+0x200] and the region [x1-0x40, x1+0x40]
    const stack = rh(c.sp, 0x200);
    const near_x1 = rh(c.x1.sub(0x40), 0x80);
    // annotate which GPRs point inside SELF (code/data) vs elsewhere
    const regOff={}; for(const r of GPR){ try{ regOff[r]=selfOff(c[r]); }catch(e){} }
    send({t:'S',n,tid:this.threadId,slot16:block.substr(0,32),
          regs, regOff, sp:c.sp.toString(), stack, near_x1});
    if(n>=MAX){done=true;send({t:'stopped',total:n});}
  }});
  return true;
}
if(Process.findModuleByName(SO))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

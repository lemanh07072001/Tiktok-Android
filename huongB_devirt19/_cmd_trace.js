// _cmd_trace.js — Trace the VM closure queue at thunk 0xa1004 to find the PRODUCER command.
// Descriptor layout (from disasm of 0xa1004): [0]=fn, [8]=argP(x0), [0x10]=len(x1), [0x18]=argD(x2), [0x20]=ret.
// EVERY native command flows through here. The slot16 SM3 command has fn=0x9fdac, len=16, argP=P (slot16 buf).
// The PRODUCER is an earlier command whose one of its arg pointers == that same P (P as output). Log fn + all
// pointer args + 16 bytes at each, in order; correlate offline: match a later SM3 command's P to an earlier
// command's arg -> that earlier fn is the producer.
'use strict';
const SO='libmetasec_ov.so';
const THUNK=0xa1004;
let base=null, lo=null, hi=null, n=0; const MAX=400;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16); }catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function rdp(p){ try{ return p.readPointer(); }catch(e){ return null; } }
function rdu(p){ try{ return p.readU64().toString(); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(THUNK), { onEnter(args){
    if(n>=MAX) return; n++;
    const desc=this.context.x0;                         // x0 = descriptor
    if(!desc){ return; }
    const fn=rdp(desc);                                  // [0]
    const a0=rdp(desc.add(8));                            // [8] argP
    const len=rdu(desc.add(0x10));                        // [0x10]
    const a2=rdp(desc.add(0x18));                         // [0x18] argD
    const rec={t:'CMD', n:n, tid:this.threadId, fn:fn?off(fn):null,
               a0:a0?a0.toString():null, len:len, a2:a2?a2.toString():null};
    // dump 16 bytes at arg pointers that look like arena/heap
    if(a0){ rec.d0=peek(a0,16); }
    if(a2){ rec.d2=peek(a2,16); }
    send(rec);
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', n:n}); }, 4000);

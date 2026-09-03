// _vm_args.js — Find where the slot16 out-pointer P enters the call chain as an ARGUMENT.
// If VM 0x55950 (or a frame above) receives P as an out-arg, we can read P at that entry BEFORE the
// producer writes it, then arm our proven 8-byte WP on P to trap the producer store.
// Method: hook VM 0x55950 entry -> dump x0..x7 (+ what each pointer-arg into the arena currently holds).
//   Hook reader (0x172a50, ret 0xa0440, sz16) -> report P. Interleave via a global seq on the same thread;
//   an arg register equal to (or pointing near) the next reader's P reveals the out-pointer path.
'use strict';
const SO='libmetasec_ov.so';
const VM=0x55950, COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, seq=0, nVM=0, nRd=0;
const MAXV=14, MAXR=22;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function inArena(p){ try{ const s=p.toString(); return s.length>=6 && s.indexOf('0x77e4')===0; }catch(e){ return false; } }
function peek(p){ try{ return hx(p.readByteArray(16)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(VM), { onEnter(args){
    if(nVM>=MAXV) return;
    nVM++; const s=++seq;
    const a=[];
    for(let i=0;i<8;i++){
      let v=null; try{ v=this.context['x'+i]; }catch(e){}
      if(!v){ try{ v=args[i]; }catch(e){} }
      const vs=v?v.toString():null;
      const entry={i:i, v:vs};
      if(v && inArena(v)){ entry.arena=true; entry.holds=peek(v); }
      a.push(entry);
    }
    send({t:'VM', seq:s, tid:this.threadId, args:a});
  }});
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(nRd>=MAXR) return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nRd++; const s=++seq;
    send({t:'RD', seq:s, tid:this.threadId, P:src.toString(), val:val});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', nVM:nVM, nRd:nRd}); }, 5000);

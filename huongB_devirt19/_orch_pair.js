// _orch_pair.js — Pair the orchestrator's per-field work buffer W (x8+24 at entry) with that field's P.
// ORCH 0x94d08 is per-field on the reader thread. Sequence per call: entry -> produce(writes P) -> hash(P)x2.
// Capture at entry AND leave: full x8 struct (64B) + deref of the arena pointer at x8+24 (32B). Tag each
// reader with the current field id + W. Offline: derive P = f(W) so we can arm the WP at entry, next field.
'use strict';
const SO='libmetasec_ov.so';
const ORCH=0x94d08, COPY=0x172a50, READBUCKET=0xa0440;
let base=null, lo=null, hi=null, fid=0, curW=null, curFid=0, nO=0, nR=0; const MAXO=16, MAXR=30;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function rdptr(p){ try{ return p.readPointer(); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(ORCH), {
    onEnter(args){
      if(nO>=MAXO) return; nO++; const id=++fid; this.id=id; this.log=true;
      const x8=this.context.x8;
      const wptr=x8?rdptr(x8.add(24)):null;
      curW=wptr?wptr.toString():null; curFid=id;
      send({t:'OENTER', id:id, tid:this.threadId, x8:x8?x8.toString():null,
            struct:x8?peek(x8,64):null, W:curW, Wmem:wptr?peek(wptr,32):null});
    },
    onLeave(ret){
      if(!this.log) return;
      const x8=this.context.x8;
      const wptr=x8?rdptr(x8.add(24)):null;
      send({t:'OLEAVE', id:this.id, W:wptr?wptr.toString():null,
            struct:x8?peek(x8,64):null, Wmem:wptr?peek(wptr,32):null});
    }
  });
  Interceptor.attach(base.add(COPY), { onEnter(args){
    if(nR>=MAXR) return;
    let src,sz; try{ src=args[1]; sz=args[2].toInt32(); }catch(e){ return; }
    if(sz!==16) return;
    let ra=null; try{ ra=this.returnAddress; }catch(e){}
    if(!ra || !inSelf(ra) || ra.sub(base).toString(16)!==READBUCKET.toString(16)) return;
    let val=null; try{ val=hx(src.readByteArray(16)); }catch(e){}
    if(!val || val==='00000000000000000000000000000000') return;
    nR++;
    send({t:'RD', fid:curFid, W:curW, tid:this.threadId, P:src.toString(), val:val});
  }});
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){ send({t:'mon', nO:nO, nR:nR}); }, 5000);

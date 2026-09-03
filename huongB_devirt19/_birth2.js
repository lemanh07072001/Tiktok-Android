/* _birth2.js — at hex_to_bytes(0x891f4): read src hexstring V, its object addr,
 * and full ACCURATE backtrace (to find producer/init parent frames beyond fp-walk).
 * Track srcObjAddr stability across repeats. Confirm at SM3-driver 0x9fd98. */
'use strict';
const SO='libmetasec_ov.so';
const OFF_HEX=0x891f4, OFF_DRIVER=0x9fd98;
let base=null, lo=null, hi=null, seq=0;
const seen={};             // V -> {addrs:Set, count}
let nbt=0; const MAXBT=14;

function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function off(p){ try{ return inSelf(p)?('+0x'+p.sub(base).toString(16)):(p+''); }catch(e){ return '?'; } }
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
function asciiOf(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++){ const c=u[i]; s+=(c>=32&&c<127)?String.fromCharCode(c):'.'; } return s; }
function readStr(objptr){
  try{ const len=objptr.add(4).readU32(); if(len<0||len>4096) return null;
    let dptr=objptr.add(8).readPointer(); let b;
    try{ b=dptr.readByteArray(len); if(b) return {len, ascii:asciiOf(b), dptr:dptr.toString()}; }catch(e){}
    try{ b=objptr.add(8).readByteArray(len); if(b) return {len, ascii:asciiOf(b), dptr:objptr.add(8).toString()}; }catch(e){}
  }catch(e){}
  return null;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});

  Interceptor.attach(base.add(OFF_HEX),{
    onEnter(args){
      const obj=this.context.x0; const s=readStr(obj);
      if(!s || s.len!==32) return;
      const V=s.ascii.replace(/\./g,'').toLowerCase();
      if(!/^[0-9a-f]{32}$/.test(V)) return;
      const mySeq=seq++;
      if(!seen[V]){ seen[V]={addrs:{}, count:0}; }
      seen[V].addrs[s.dptr]=(seen[V].addrs[s.dptr]||0)+1; seen[V].count++;
      const firstTime = seen[V].count===1;
      if(firstTime && nbt<MAXBT){
        nbt++;
        let bt=[];
        try{ bt=Thread.backtrace(this.context, Backtracer.ACCURATE).map(off); }catch(e){ bt=['bt_err']; }
        send({t:'BIRTHBT', seq:mySeq, v:V, obj:obj.toString(), data:s.dptr, bt:bt});
      }
    }
  });

  Interceptor.attach(base.add(OFF_DRIVER),{
    onEnter(args){
      let len; try{ len=parseInt(this.context.x1.toString())&0xffffffff; }catch(e){ return; }
      if(len!==16) return;
      let val; try{ val=hx(this.context.x0.readByteArray(16)); }catch(e){ return; }
      if(/^0+$/.test(val)) return;
      send({t:'DRV', seq:seq, slot16:val});
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,200); }; setTimeout(t,300); }
setInterval(function(){
  // summarize address-stability per value
  const rep={}; for(const v in seen){ rep[v]={n:seen[v].count, addrs:Object.keys(seen[v].addrs).length}; }
  send({t:'mon', seq:seq, seen:rep});
}, 4000);

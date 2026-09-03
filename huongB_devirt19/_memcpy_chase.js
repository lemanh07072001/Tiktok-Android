// _memcpy_chase.js — Follow the DATA, not the control flow. slot16 lands in buffer P (arena 0x77e4…) and is
// consumed by the SM3 driver. From _wp_reuse we know P is filled by a copy. Hook memcpy/memmove, filter to
// copies touching the 0x77e4 arena band (cheap range check => low overhead), and ring-store {dst,src,16B,ra}.
// At the driver (P holds slot16 V), look up P -> src (producer output buffer), then chain src->src2->… to the
// ORIGIN. The memcpy's returnAddress in libmetasec pinpoints the code that assembles slot16 = producer's
// immediate neighbor. No exception handler (that + memcpy hook is what killed v1); gate after 12s; auto-detach.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const BAND_LO=ptr('0x77e400000000'), BAND_HI=ptr('0x77e600000000');
let base=null, lo=null, hi=null, safe=false, ndrv=0; const MAXD=6;
const listeners=[]; let detached=false;
const byDst={};        // dst(str) -> {src,b,ra,seq}
let seq=0, stored=0; const STOREMAX=40000;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function inBand(p){ try{ return p.compare(BAND_LO)>=0 && p.compare(BAND_HI)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function hookcpy(name){ const a=Module.findGlobalExportByName(name); if(!a) return;
  listeners.push(Interceptor.attach(a,{ onEnter(args){ if(!safe||detached) return;
    let len=0; try{ len=args[2].toInt32(); }catch(e){ return; } if(len!==16 && len!==32) return;
    const dst=args[0], src=args[1]; if(!inBand(dst) && !inBand(src)) return;
    let ra=null; try{ const r=this.returnAddress; ra=selfOff(r)||null; }catch(e){}
    const b=peek(src,16); if(!b) return;
    byDst[dst.toString()]={src:src.toString(), b:b, ra:ra, len:len, seq:++seq};
    if(++stored>STOREMAX) detachAll();
  }}));
}
function detachAll(){ if(detached) return; detached=true; listeners.forEach(function(l){ try{l.detach();}catch(e){} }); send({t:'detached', stored:stored}); }
function chase(P){ const chain=[]; let cur=P; const seen={};
  for(let i=0;i<8;i++){ const r=byDst[cur]; if(!r) { chain.push({dst:cur, note:'no-writer(origin?)'}); break; }
    chain.push({dst:cur, src:r.src, b:r.b, ra:r.ra, len:r.len, srcInSelf:inSelf(ptr(r.src)), srcInBand:inBand(ptr(r.src))});
    if(seen[r.src]) { chain.push({note:'cycle'}); break; } seen[cur]=1; cur=r.src;
  }
  return chain;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  hookcpy('memcpy'); hookcpy('memmove');
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    const chain=chase(c.x0.toString());
    // does any chain node's bytes equal V? mark it
    chain.forEach(function(n){ if(n.b===V) n.matchesV=true; });
    send({t:'DRV', drv:ndrv, V:V, P:c.x0.toString(), chain:chain});
    if(ndrv>=MAXD) detachAll();
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 12000);
setTimeout(function(){ detachAll(); }, 30000);
setInterval(function(){ send({t:'mon', safe:safe, seq:seq, stored:stored, ndrv:ndrv, detached:detached}); }, 3000);

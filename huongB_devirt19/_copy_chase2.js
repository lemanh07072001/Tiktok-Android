// _copy_chase2.js — v2 of the data-follow: previous memcpy_chase filtered ONLY len∈{16,32} and saw zero
// arena-band copies, but _wp_reuse observed a libc++ memmove re-copying slot16 into P — so the copy width is
// likely NOT 16/32 (slot16 travels inside a wider struct). Here we widen to len∈[8,4096], hook memcpy+memmove,
// filter (dst in band) OR (src in band), ring-store {dst,src,len,first32,ra}. At the SM3-driver (P holds slot16
// V), report every copy where P ∈ [dst,dst+len) (P was WRITTEN by this copy => src+offset = producer output) OR
// P ∈ [src,src+len) (P was COPIED OUT). If nothing lands, P is written by inline native stores (no libc copy)
// => escalate to allocator-hook + HW-watchpoint on fresh P. Safe: 2 point-hooks + range filter; gate 10s.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const BAND_LO=ptr('0x7000000000'), BAND_HI=ptr('0x8000000000'); // FIX: prior 0x77e4_00000000 had 2 extra 0s => P(0x77e4xxxxxx) never matched, invalidating the earlier "0 copies" result
let base=null, lo=null, hi=null, safe=false, ndrv=0; const MAXD=8;
const RING=[]; const RMAX=30000; let stored=0, seen=0;
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function inBand(p){ try{ return p.compare(BAND_LO)>=0 && p.compare(BAND_HI)<0; }catch(e){ return false; } }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function hookcpy(name){ const a=Module.findGlobalExportByName(name); if(!a) return;
  Interceptor.attach(a,{ onEnter(args){ if(!safe) return; seen++;
    let len=0; try{ len=args[2].toInt32(); }catch(e){ return; } if(len<8||len>4096) return;
    const dst=args[0], src=args[1]; if(!inBand(dst) && !inBand(src)) return;
    let ra=null; try{ ra=selfOff(this.returnAddress); }catch(e){}
    RING.push({dst:dst.toString(), src:src.toString(), len:len, b:peek(src,Math.min(len,32)), ra:ra, fn:name});
    if(RING.length>RMAX) RING.shift(); stored++;
  }});
}
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  hookcpy('memcpy'); hookcpy('memmove'); hookcpy('__memcpy_chk'); hookcpy('__memmove_chk');
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    const P=c.x0;
    const wrote=[], readout=[];
    for(let i=RING.length-1;i>=0 && (wrote.length+readout.length)<30;i--){ const r=RING[i];
      let d=null,s=null; try{ d=ptr(r.dst); s=ptr(r.src);}catch(e){continue;}
      // P inside dst range?
      if(P.compare(d)>=0 && P.compare(d.add(r.len))<0){ const rel=P.sub(d).toInt32(); wrote.push({rel:rel, srcAt:s.add(rel).toString(), len:r.len, b:r.b, ra:r.ra, fn:r.fn}); }
      if(P.compare(s)>=0 && P.compare(s.add(r.len))<0){ const rel=P.sub(s).toInt32(); readout.push({rel:rel, dstAt:d.add(rel).toString(), len:r.len, ra:r.ra, fn:r.fn}); }
    }
    send({t:'DRV', drv:ndrv, V:V, P:P.toString(), wrote:wrote, readout:readout, stored:stored, seen:seen});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 10000);
setInterval(function(){ send({t:'mon', safe:safe, ndrv:ndrv, stored:stored, seen:seen}); }, 3000);

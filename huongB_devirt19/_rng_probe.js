// _rng_probe.js — DECISIVE cheap fork: is slot16 a client NONCE (from libc RNG) or a deterministic PRF?
// The producer writes P via inline stores (memcpy ruled out). But if those 16 bytes ORIGINATE from a libc
// randomness source, we catch them at the libc boundary regardless of how they're later stored. libmetasec
// imports only rand/srand/lrand48 (per dynsym), but we also net the buffer-fillers (arc4random_buf,getrandom).
// Strategy: hook each RNG export; ring-buffer recent outputs (value + return-addr in SELF). At the SM3-driver
// (x0=P holds slot16 V, w1=16) check whether V (or its halves/words) matches recent RNG output — if yes,
// slot16 = nonce (offline-generatable, skip the ARX crack); if the ring is empty of matches over many DRVs,
// slot16 is NOT random => justify the heavy Stalker producer-trace. Also log per-RNG call counts to see if
// any RNG even fires near the init burst. Safe: few RNG calls; gate after 10s.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, safe=false, ndrv=0; const MAXD=8;
const RING=[]; const RINGMAX=6000; const calls={};
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return null; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
// little-endian hex of an integer value in `bits` bytes (for matching rand() ints inside V byte-string)
function le(vNum, bytes){ let s=''; for(let i=0;i<bytes;i++){ s+=('0'+(Number((vNum>>BigInt(8*i))&0xffn)).toString(16)).slice(-2); } return s; }
function push(rec){ RING.push(rec); if(RING.length>RINGMAX) RING.shift(); }
function hookInt(name, retBytes){ const a=Module.findGlobalExportByName(name); if(!a) return;
  Interceptor.attach(a,{ onLeave(ret){ if(!safe) return; calls[name]=(calls[name]||0)+1;
    let ra=null; try{ ra=selfOff(this.returnAddress); }catch(e){}
    let v=0n; try{ v=BigInt(ret.toString())&((1n<<BigInt(8*retBytes))-1n); }catch(e){}
    push({fn:name, hexLE:le(v, retBytes), fromSelf:!!ra, ra:ra}); } }); }
function hookBuf(name){ const a=Module.findGlobalExportByName(name); if(!a) return;
  Interceptor.attach(a,{ onEnter(args){ this.buf=args[0]; this.len=(function(){try{return args[1].toInt32();}catch(e){return 0;}})(); },
    onLeave(){ if(!safe) return; calls[name]=(calls[name]||0)+1; let ra=null; try{ ra=selfOff(this.returnAddress);}catch(e){}
      const b=peek(this.buf, Math.min(this.len||0,64)); push({fn:name, hexLE:b, len:this.len, fromSelf:!!ra, ra:ra}); } }); }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  ['rand','random','lrand48','mrand48','nrand48','jrand48','arc4random'].forEach(function(n){ hookInt(n,4); });
  hookInt('lrand48',4); hookInt('mrand48',4);
  ['arc4random_buf','getrandom'].forEach(hookBuf);
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(!safe||ndrv>=MAXD) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const V=peek(c.x0,16); if(!V||V==='00000000000000000000000000000000') return; ndrv++;
    // match V (or its 4-byte words / 8-byte halves) against recent RNG outputs
    const hits=[]; const words=[V.slice(0,8),V.slice(8,16),V.slice(16,24),V.slice(24,32)]; // 4x u32 (LE hex)
    for(let i=RING.length-1;i>=0 && hits.length<12;i--){ const r=RING[i]; if(!r.hexLE) continue;
      if(V.indexOf(r.hexLE)>=0 || (r.hexLE.length>=8 && (words.indexOf(r.hexLE.slice(0,8))>=0))) hits.push(r);
    }
    send({t:'DRV', drv:ndrv, V:V, P:c.x0.toString(), rngHits:hits, ringLen:RING.length, callsNow:calls}); }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 10000);
setInterval(function(){ send({t:'mon', safe:safe, ndrv:ndrv, ringLen:RING.length, calls:calls}); }, 3000);

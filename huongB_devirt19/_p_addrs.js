// _p_addrs.js — Decide the persistent-field hypothesis: do slot16 buffer ADDRESSES recur across heartbeats?
// If some P address repeats, slot16 lives at a fixed offset in a long-lived object => we can arm a PERMANENT
// WP on that address early and catch the PRODUCER writing the NEXT request's value (breaking the past-write wall).
// If every P is unique, slot16 lives in transient STL buffers => need a different producer-catch (upstream walk).
// Pure observation: hook driver, log (seq, P, val16, thread). Also read lr + the caller's lr from the frame to
// get a coarse call-site fingerprint. No WP, no hooks beyond the driver => safe.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, n=0; const MAX=400;
const addrCount={};      // P -> count
const valCount={};       // val16 -> count
const addrVals={};       // P -> Set of vals (as array)
function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function selfOff(p){ try{ if(inSelf(p)) return 'SELF+0x'+p.sub(base).toString(16);}catch(e){} return p?p.toString():'0'; }
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function peek(p,n){ try{ return hx(p.readByteArray(n)); }catch(e){ return null; } }
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size); send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(n>=MAX) return; const c=this.context; const P=c.x0;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    const v0=peek(P,16); if(!v0||v0==='00000000000000000000000000000000') return; n++;
    const ps=P.toString();
    addrCount[ps]=(addrCount[ps]||0)+1; valCount[v0]=(valCount[v0]||0)+1;
    if(!addrVals[ps]) addrVals[ps]=[]; if(addrVals[ps].indexOf(v0)<0) addrVals[ps].push(v0);
    if(n<=40) send({t:'S', n:n, P:ps, val:v0, lr:selfOff(c.lr), tid:this.threadId});
  }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setInterval(function(){
  const addrs=Object.keys(addrCount); const reused=addrs.filter(function(a){return addrCount[a]>1;});
  const distinctVals=Object.keys(valCount).length; const repVals=Object.keys(valCount).filter(function(v){return valCount[v]>1;}).length;
  send({t:'mon', n:n, distinctAddrs:addrs.length, reusedAddrs:reused.length,
        distinctVals:distinctVals, repeatedVals:repVals,
        topReuse:reused.map(function(a){return [a,addrCount[a],addrVals[a].length];}).sort(function(x,y){return y[1]-x[1];}).slice(0,6)});
}, 3000);

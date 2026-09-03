// _slot16_provenance.js — Route B (safe, no MAM): trace slot16's copy provenance.
// Hook metasec-internal copy prims (memcpy 0x172a50, memmove 0x5ade0). Record every call
// (counter, fn, src, dst, len, first bytes of src, caller-in-SO). On nonzero #19 slot16,
// dump the ring; the EARLIEST record whose src/dst holds slot16 = origin buffer, its caller
// = near the producer. Pure Interceptor => cannot hang the app.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748, MEMCPY=0x172a50, MEMMOVE=0x5ade0;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function hxab(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
let base=null, lo=null, hi=null;
function soOff(a){ if(a && a.compare(lo)>=0 && a.compare(hi)<0) return '0x'+a.sub(base).toString(16); return null; }
function region(a){ try{const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection;}catch(e){} return '?'; }
const ring=[]; let ctr=0; const RINGMAX=600;
const chain={};
function rec(fn,src,dst,len){
  if(len<16||len>4096) return;
  let ra=null; try{ ra=soOff((this&&this.returnAddress)||ptr(0)); }catch(e){}
  const srcHex=hx(src, Math.min(len,96));
  ring.push({i:++ctr, fn:fn, src:src.toString(), dst:dst.toString(), len:len, ra:ra, srcHex:srcHex});
  if(ring.length>RINGMAX) ring.shift();
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  try{ Interceptor.attach(base.add(MEMCPY),{onEnter(a){ rec.call(this,'cpy',a[1],a[0],a[2].toInt32()); }}); }catch(e){ send({t:'info',msg:'cpy hook fail '+e}); }
  try{ Interceptor.attach(base.add(MEMMOVE),{onEnter(a){ rec.call(this,'mov',a[1],a[0],a[2].toInt32()); }}); }catch(e){ send({t:'info',msg:'mov hook fail (skip) '+e}); }
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hxab(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot='',pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    delete chain[tid];
    if(slot==='00'.repeat(16)||pr>=12) return;
    // find ring records whose srcHex contains slot16 (i.e., the copy carried slot16)
    const carriers=ring.filter(r=>r.srcHex && r.srcHex.indexOf(slot)>=0).map(r=>({i:r.i,fn:r.fn,ra:r.ra,src:r.src,dst:r.dst,len:r.len,off:r.srcHex.indexOf(slot)/2,srcHead:r.srcHex.slice(0,64)}));
    send({t:'hit', slot16:slot, ncarriers:carriers.length, carriers:carriers.slice(0,12), ringlen:ring.length});
  }});
  send({t:'info',msg:'provenance installed base='+base+' size=0x'+m.size.toString(16)});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

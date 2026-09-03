// _slot16_locate.js — detect nonzero slot16 (relaxed, hook SM3) then Memory.scan writable
// ranges for that 16-byte pattern => report ALL locations + region. The persistent copy
// (stable module/heap, not the transient SM3 input) = producer's output buffer.
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection+' base='+r.base; }catch(e){}
  return 'anon?';
}
function scanFor(hexpat){
  const pat=hexpat.match(/../g).map(h=>parseInt(h,16));
  const patStr=pat.map(b=>('0'+b.toString(16)).slice(-2)).join(' ');
  const ranges=Process.enumerateRanges('rw-');
  const hits=[];
  for(const r of ranges){
    if(r.size>32*1024*1024) continue;
    try{
      const found=Memory.scanSync(r.base,r.size,patStr);
      for(const f of found){ hits.push({addr:f.address.toString(), region:region(f.address)}); if(hits.length>=40) break; }
    }catch(e){}
    if(hits.length>=40) break;
  }
  return hits;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base; const chain={}; const seen={}; let done=0;
  Interceptor.attach(base.add(SM3),{onEnter(){
    if(done>=3) return;
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;
    if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    let qhead=''; for(let i=0;i<Math.min(40,mlen);i++) qhead+=String.fromCharCode(a[i]);
    if(slot!=='00'.repeat(16)&&pr<12&&!seen[slot]){
      seen[slot]=1; done++;
      const hits=scanFor(slot);
      send({t:'loc', slot16:slot, qhead:qhead, mlen:mlen, nhits:hits.length, hits:hits});
    }
    delete chain[tid];
  }});
  send({t:'info',msg:'slot16-locate installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

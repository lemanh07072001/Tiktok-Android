// _slot16_home.js — Determine slot16's memory HOMES and their STABILITY across requests.
// 1) learn live slot16 from SM3 #19 input (query||slot16||'0') at 0xa0748 (reliable detector)
// 2) on first nonzero slot16, snapshot ALL rw- addresses holding those 16 bytes (+region+file)
// 3) re-snapshot on later requests -> addresses present in >1 snapshot = STABLE cache home
//    (fresh SM3/header buffers appear once; a persistent cache home appears every time)
'use strict';
const SO='libmetasec_ov.so', SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(ab){const u=new Uint8Array(ab);let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}
function regionOf(a){
  try{const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){}
  try{const r=Process.findRangeByAddress(a); if(r) return (r.file?('FILE:'+r.file.path):'[anon]')+' '+r.protection;}catch(e){}
  return 'unknown';
}
function scanAll(hexval){
  const pat=hexval.replace(/(..)/g,'$1 ').trim();
  const homes=[];
  const ranges=Process.enumerateRanges('rw-');
  for(const r of ranges){
    try{
      const hits=Memory.scanSync(r.base, r.size, pat);
      for(const h of hits) homes.push({addr:h.address.toString(), region:regionOf(h.address)});
    }catch(e){}
    if(homes.length>200) break;
  }
  return homes;
}
const chain={}; let snaps=0; let learned=null; const MAXSNAP=6; const snapHist={};
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  Interceptor.attach(m.base.add(SM3),{onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return;
    let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80){return;}
    if(a[mlen-1]!==0x30||mlen<200){ delete chain[tid]; return; }
    let f=''; for(let i=0;i<mlen;i++) f+=String.fromCharCode(a[i]);
    if(f.indexOf('device_platform=')<0){ delete chain[tid]; return; }
    let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot+=('0'+a[i].toString(16)).slice(-2);
    delete chain[tid];
    if(slot==='00'.repeat(16)){ send({t:'slot',kind:'ZERO'}); return; }
    if(snaps>=MAXSNAP) return;
    snaps++;
    if(!learned) learned=slot;
    const homes=scanAll(slot);
    homes.forEach(h=>{ snapHist[h.addr]=(snapHist[h.addr]||0)+1; });
    send({t:'snap', n:snaps, slot16:slot, nhomes:homes.length, homes:homes.slice(0,40)});
  }});
  send({t:'info',msg:'slot16-home installed base='+m.base});
  return true;
}
function report(){ send({t:'stable', hist:snapHist}); }
rpc.exports={report:report};
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

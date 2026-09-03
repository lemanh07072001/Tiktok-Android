// _psk_flow.js — trace the PSK's data-flow. Hook internal memcpy 0x172a50; catch every copy whose src
// holds the known PSK (b2a9d40c...). Report src->dst + region + backtrace. The EARLIEST/deepest src =
// the PSK generator's output buffer. (Same technique that mapped slot16's flow.)
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
const PSK16='b2a9d40c622aedce93a5e22f03780a67';  // first 16B of PSK (marker)
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path.split('/').pop():'anon')+' '+r.protection; }catch(e){} return '?'; }
const seen={}; let n=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(n>=20) return; const len=a[2].toInt32(); if(len<16||len>4096) return;
    const src=a[1]; let buf; try{ buf=new Uint8Array(ptr(src).readByteArray(Math.min(len,256))); }catch(e){ return; }
    // find PSK16 marker anywhere in src
    let hexs=''; for(let i=0;i<buf.length;i++) hexs+=('0'+buf[i].toString(16)).slice(-2);
    const idx=hexs.indexOf(PSK16);
    if(idx<0) return; const off=idx/2;
    const srcAt=ptr(src).add(off);
    const key=region(srcAt); if(seen[key]) return; seen[key]=1; n++;
    let ret=null; try{ ret=this.returnAddress; }catch(e){}
    const chainRA=[]; if(ret) chainRA.push(ret+' '+region(ret));
    try{ const sp=this.context.sp; for(let o=0;o<0x400 && chainRA.length<12;o+=8){ let v; try{v=sp.add(o).readPointer();}catch(e){break;}
      if(v.compare(lo)>=0&&v.compare(hi)<0) chainRA.push(v+' '+region(v)); } }catch(e){}
    send({t:'flow', srcAt:srcAt.toString(), src_region:region(srcAt), dst:a[0].toString(), dst_region:region(a[0]), len:len, off:off, before16:hx(srcAt.sub(16),16), chainRA:chainRA});
  }});
  send({t:'info',msg:'psk-flow installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

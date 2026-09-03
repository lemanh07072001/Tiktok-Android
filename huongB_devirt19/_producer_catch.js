// _producer_catch.js — catch the PRODUCER writing slot16 into the header k-v structure.
// Header entry layout: [020102000000 keyid2B][8 zero][slot16 16B][ascii keyname e.g. K-VERSION].
// Hook internal memcpy 0x172a50; when a 16-byte copy's DST lands in a header entry (tag 020102
// present just before, or ascii keyname just after) => src = producer's crypto output, bt = producer.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){}
  return 'anon?';
}
function isHentropy(p){ // src 16 bytes: nonzero, mostly non-ascii, not constant
  try{ const u=new Uint8Array(ptr(p).readByteArray(16)); let zero=0,asc=0,set={};
    for(let i=0;i<16;i++){ if(u[i]===0)zero++; if(u[i]>=0x20&&u[i]<=0x7e)asc++; set[u[i]]=1; }
    return zero<=4 && asc<12 && Object.keys(set).length>=10;
  }catch(e){ return false; }
}
const seen={}; let cnt=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    const len=a[2].toInt32(); if(len<16||len>32) return;
    const dst=a[0], src=a[1];
    if(!isHentropy(src)) return;
    // examine dst neighborhood (already-written tag before / keyname after where value goes)
    let pre,post; try{ pre=hx(dst.sub(10),10); post=hx(dst.add(16),16); }catch(e){ return; }
    if(!pre||!post) return;
    const tagHit = pre.slice(0,12)==='020102000000';
    // keyname ascii after value: bytes like 4b2d (K-) / 484f5354 (HOST) / 2d544e43 (-TNC)
    const kn = post;
    const knAscii = /^(4b2d|484f5354|2d544e43|4b2d564552)/.test(kn);
    if(!tagHit && !knAscii) return;
    const key=dst.toString();
    if(seen[key]||cnt>=12) return; seen[key]=1; cnt++;
    let ret=null; try{ ret=this.returnAddress; }catch(e){}
    const chainRA=[]; if(ret) chainRA.push(ret+' '+region(ret));
    try{ const sp=this.context.sp; for(let o=0;o<0x500 && chainRA.length<14;o+=8){ let v; try{v=sp.add(o).readPointer();}catch(e){break;}
      if(v.compare(lo)>=0&&v.compare(hi)<0) chainRA.push(v+' '+region(v)); } }catch(e){}
    send({t:'prod', value16:hx(src,16), src:src.toString(), src_region:region(src), dst:dst.toString(), dst_region:region(dst),
          len:len, dst_pre10:pre, dst_post16:post, tagHit:tagHit, knAscii:knAscii, chainRA:chainRA});
  }});
  send({t:'info',msg:'producer-catch installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

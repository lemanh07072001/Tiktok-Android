// _store_key_hook.js — Route B: catch the producer's slot16 at STORAGE into the keystore.
// Record fmt: [020102 00][4B id][0000][0000][16B value][keyname "K-VERSION\0"...].
// Hook memcpy 0x172a50; whenever a copy's SRC contains "K-VERSION" (4b2d56455253494f4e), the 16 bytes
// immediately BEFORE it = slot16 (producer output). Capture src/dst/len + those 16B + caller chain.
// If the whole record is copied, SRC = producer's assembled buffer -> its writer = producer.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
const KV='4b2d56455253494f4e';                     // "K-VERSION"
function hxread(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
let base=null,lo,hi; let n=0;
function soWalk(ctx){ const st=[]; try{ const sp=ctx.sp;
  for(let o=0;o<0x900 && st.length<20;o+=8){ let v; try{v=sp.add(o).readPointer();}catch(e){break;}
    if(v.compare(lo)>=0&&v.compare(hi)<0) st.push('libmetasec+0x'+v.sub(base).toString(16)); } }catch(e){} return st; }
function region(a){ try{const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection;}catch(e){} return '?'; }
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(n>=8) return;
    const len=a[2].toInt32(); if(len<9||len>65536) return;
    const src=a[1];
    const head=hxread(src, Math.min(len,320)); if(!head) return;
    const k=head.indexOf(KV); if(k<0) return;             // src carries "K-VERSION"
    const bytePos=k/2;                                    // byte offset of keyname in src
    let ra=null; try{ra=this.returnAddress;}catch(e){}
    const raoff=(ra&&ra.compare(lo)>=0&&ra.compare(hi)<0)?('0x'+ra.sub(base).toString(16)):(''+ra);
    // 16B value immediately before keyname = slot16 (if bytePos>=16)
    const val16 = bytePos>=16 ? head.slice((bytePos-16)*2, bytePos*2) : null;
    n++;
    send({t:'kv', i:n, src:src.toString(), srcRegion:region(src), dst:a[0].toString(), dstRegion:region(a[0]),
          len:len, kvBytePos:bytePos, val16:val16, ra:raoff, srcHead:head.slice(0, Math.min(head.length, 2*(bytePos+16))), stack:soWalk(this.context)});
  }});
  send({t:'info',msg:'store-key-hook installed base='+base});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

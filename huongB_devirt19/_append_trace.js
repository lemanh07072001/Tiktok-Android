// _append_trace.js — hook INTERNAL memcpy 0x172a50 (dst=x0,src=x1,len=x2), found in SM3-caller
// buffer-assembly. Catch the append that places a (recurring) slot16 => src = pool source addr.
'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
// recurring pool values observed across spawns (targets)
const TARGETS=['cb12155b4933d1500308499e4fcb6694','b8591fcb8d86ff40ed3989462a588bf1',
               '9ae50e6bfa15208a2bc1ec3fa91835cc','c05e3c8868e69ebd08a7ba993ba2d5b9',
               '61baee757d05f9f145b9704c3476e86c','b67409ad2dd87d9fb617057170991ba8'];
const TSET={}; TARGETS.forEach(t=>TSET[t]=1);
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){}
  return 'anon?';
}
const seen={}; let cnt=0, calls=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    calls++;
    const len=a[2].toInt32();
    if(len<16||len>4096) return;
    const src=a[1];
    // scan the first min(len,512) bytes of src for a target slot16 at any 1-byte offset
    let buf; try{ buf=new Uint8Array(ptr(src).readByteArray(Math.min(len,512))); }catch(e){ return; }
    for(let off=0; off+16<=buf.length; off++){
      let s=''; for(let i=0;i<16;i++) s+=('0'+buf[off+i].toString(16)).slice(-2);
      if(TSET[s]){
        const srcAt=ptr(src).add(off);
        const key=s+'@'+srcAt;
        if(seen[key]||cnt>=10) return; seen[key]=1; cnt++;
        // safe caller chain
        let ret=null; try{ ret=this.returnAddress; }catch(e){}
        const chainRA=[]; if(ret) chainRA.push(ret+' '+region(ret));
        try{ const sp=this.context.sp;
          for(let o=0;o<0x600 && chainRA.length<16;o+=8){ let v; try{v=sp.add(o).readPointer();}catch(e){break;}
            if(v.compare(lo)>=0&&v.compare(hi)<0) chainRA.push(v+' '+region(v)); } }catch(e){}
        send({t:'app', slot16:s, src:srcAt.toString(), src_region:region(srcAt), dst:a[0].toString(), dst_region:region(a[0]), len:len, off:off, ctx48:hx(srcAt.sub(16),48), chainRA:chainRA});
        return;
      }
    }
  }});
  send({t:'info',msg:'append-trace installed on 0x'+MEMCPY.toString(16)});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

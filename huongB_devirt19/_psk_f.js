// _psk_f.js — dump F(0x191f40)'s input object-graph. Memory: F's x1 = 5 pointers into a C++ graph;
// q2 (x1[2]) = PSK-material 64B block. Hook interp 0x52924 gated x0=base+0x191f40, dump x1[0..4] + their
// 64B targets + protection. Identify PSK = device-stable high-entropy 64B rw- block. Cross-spawn confirm.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, F_PROG=0x191f40;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function protOf(a){ try{ const r=Process.findRangeByAddress(a); if(r) return r.protection+' '+(r.file?r.file.path.split('/').pop():'anon'); }catch(e){} return '?'; }
function entr(h){ if(!h)return 0; const u=h.match(/../g).map(x=>parseInt(x,16)); let s={}; for(const b of u.slice(0,32)) s[b]=1; return Object.keys(s).length; }
let cap=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(cap>=6) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==F_PROG) return; }catch(e){ return; }
    cap++;
    const x1=a[1];
    const qs=[];
    for(let i=0;i<6;i++){
      let q; try{ q=ptr(x1).add(i*8).readPointer(); }catch(e){ break; }
      const h=hx(q,64);
      qs.push({idx:i, ptr:q.toString(), prot:protOf(q), ent:entr(h), hex:h});
    }
    send({t:'finbuf', x1:x1.toString(), q:qs});
  }});
  send({t:'info',msg:'psk-f installed (F 0x191f40)'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

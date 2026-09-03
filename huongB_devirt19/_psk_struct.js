// _psk_struct.js — dump the orchestrator 0x1814f0 input object-graph CLEARLY with region protection,
// so we can identify the PSK slot: a device-stable, high-entropy 32-64B block in a WRITABLE (rw-) DATA
// region (NOT r-x code, NOT ascii string, NOT a header-entry with keyname).
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, ORCH=0x1814f0;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function prot(a){ try{ const r=Process.findRangeByAddress(a); if(r) return r.protection+(r.file?(' '+r.file.path.split('/').pop()):' anon'); }catch(e){} return '?'; }
function ent(u){ if(!u) return 0; let set={}; for(let i=0;i<u.length;i++) set[u[i]]=1; return Object.keys(set).length; }
let cap=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(cap>=4) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==ORCH) return; }catch(e){ return; }
    cap++;
    const x1=a[1];
    // BFS 3 levels from x1, dump each node with protection + entropy; flag rw- data blocks
    const nodes=[]; const seen={}; let frontier=[{p:x1,path:'x1'}];
    for(let lvl=0; lvl<3 && nodes.length<60; lvl++){
      const next=[];
      for(const f of frontier){
        for(let i=0;i<8;i++){
          let q; try{ q=ptr(f.p).add(i*8).readPointer(); }catch(e){ break; }
          const key=q.toString(); if(seen[key]||q.isNull()) continue; seen[key]=1;
          let u; try{ u=new Uint8Array(ptr(q).readByteArray(64)); }catch(e){ continue; }
          if(!u) continue;
          const pr=prot(q); const e=ent(u);
          // PSK flag: rw- writable, high entropy (>=40 distinct/64), NOT ascii-heavy, NOT keyname
          const h=hx(q,64);
          const asc=Array.from(u.slice(0,32)).filter(b=>b>=0x20&&b<=0x7e).length;
          const isData = pr.indexOf('rw-')>=0;
          const isKeyname = h.indexOf('4b2d564552')>=0;
          const pskLike = isData && e>=40 && asc<16 && !isKeyname;
          nodes.push({path:f.path+'['+i+']', at:key, prot:pr, ent:e, asc:asc, pskLike:pskLike, hex:h});
          next.push({p:q, path:f.path+'['+i+']'});
        }
      }
      frontier=next;
    }
    const psk=nodes.filter(n=>n.pskLike);
    send({t:'struct', x1:x1.toString(), nnodes:nodes.length, npsk:psk.length, psk:psk.slice(0,12), sample:nodes.slice(0,6)});
  }});
  send({t:'info',msg:'psk-struct installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

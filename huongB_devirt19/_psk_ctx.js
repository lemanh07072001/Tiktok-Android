// _psk_ctx.js — walk the DEVICE-CONTEXT object (ctxptr = [x20+0x10] at getter tail 0x13b04c) to find
// the PSK: device-stable 32-64B high-entropy block in a rw- DATA region (not code, not ascii/string).
// F read PSK from this context (memory: "q2=PSK-material 64B"). Cross-spawn => device-stable filter.
'use strict';
const SO='libmetasec_ov.so', TAIL=0x13b04c;
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function protOf(a){ try{ const r=Process.findRangeByAddress(a); if(r) return {p:r.protection, f:(r.file?r.file.path.split('/').pop():'anon')}; }catch(e){} return {p:'?',f:'?'}; }
function ent(u){ let s={}; for(let i=0;i<u.length;i++) s[u[i]]=1; return Object.keys(s).length; }
function isPtr(v){ return v.compare(ptr('0x1000000000'))>0 && v.compare(ptr('0x8000000000'))<0; }
let done=false;
function walk(root){
  const cands=[]; const seen={}; let frontier=[root];
  for(let lvl=0; lvl<5 && cands.length<80; lvl++){
    const next=[];
    for(const p of frontier){
      for(let i=0;i<16;i++){
        let q; try{ q=ptr(p).add(i*8).readPointer(); }catch(e){ break; }
        const key=q.toString(); if(seen[key]||q.isNull()||!isPtr(q)) continue; seen[key]=1;
        let u; try{ u=new Uint8Array(ptr(q).readByteArray(64)); }catch(e){ continue; }
        if(!u) continue;
        const pr=protOf(q); const e=ent(u.slice(0,32));
        const asc=Array.from(u.slice(0,32)).filter(b=>b>=0x20&&b<=0x7e).length;
        const h=hx(q,64);
        const isCode = pr.p.indexOf('x')>=0;
        const isKeyname = h.indexOf('4b2d564552')>=0;
        // PSK-like: rw- writable data, high entropy (>=28/32 distinct), few ascii, not code, not keyname
        if(pr.p.indexOf('rw-')>=0 && !isCode && e>=28 && asc<14 && !isKeyname){
          cands.push({at:key, prot:pr.p+' '+pr.f, ent:e, asc:asc, hex:h});
        }
        next.push(q);
      }
    }
    frontier=next;
  }
  return cands;
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base;
  Interceptor.attach(base.add(TAIL),{onEnter(){
    if(done) return;
    try{
      const ctxptr=this.context.x20.add(0x10).readPointer();
      if(ctxptr.isNull()||!isPtr(ctxptr)) return;
      done=true;
      const cands=walk(ctxptr);
      // dedup by hex
      const seen={}; const uniq=cands.filter(c=>{ if(seen[c.hex])return false; seen[c.hex]=1; return true; });
      send({t:'ctxpsk', ctxptr:ctxptr.toString(), ncand:uniq.length, cand:uniq.slice(0,20)});
    }catch(e){ send({t:'info',msg:'walk err '+e}); }
  }});
  send({t:'info',msg:'psk-ctx installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

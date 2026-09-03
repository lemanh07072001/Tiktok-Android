// _psk_find.js — LOCATE the device PSK (32B device-stable secret) + hunt its GENERATOR.
// Strategy (mirrors the slot16 devirt): PSK is the input to the slot16 crypto (orchestrator 0x1814f0).
// 1) Learn the pool slot16 (SM3 hook) so we know a real crypto run happened.
// 2) The crypto orchestrator 0x1814f0 reads PSK from its input object-graph (x1). Hook 0x1814f0 entry,
//    walk x1's graph, dump candidate 32-byte high-entropy blocks = PSK candidates (device-stable).
// 3) Cross-run: PSK is device-stable => the SAME 32B appears across spawns. Record + compare offline.
// 4) Then (next step) trace WHERE that 32B is first WRITTEN on a FRESH state = PSK-generation program.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924, SM3=0xa0748, ORCH=0x1814f0;
const IV='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
function hx(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){ try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16);}catch(e){} return 'anon?'; }
function hentropy(u){ let zero=0,asc=0,set={}; for(let i=0;i<u.length;i++){ if(u[i]===0)zero++; if(u[i]>=0x20&&u[i]<=0x7e)asc++; set[u[i]]=1; } return zero<=6&&asc<u.length*0.6&&Object.keys(set).length>=Math.min(20,u.length); }
const pool={}; let cap=0;
function walk(p, out, depth){ if(depth>2) return; try{
  for(let i=0;i<10;i++){ let q; try{ q=ptr(p).add(i*8).readPointer(); }catch(e){ break; }
    // dump 32B at q; if high-entropy => PSK candidate
    let u; try{ u=new Uint8Array(ptr(q).readByteArray(32)); }catch(e){ continue; }
    if(u && hentropy(u)){ out.push({at:q.toString(), region:region(q), hex32:hx(q,32)}); }
    walk(q, out, depth+1);
    if(out.length>=40) return;
  } }catch(e){}
}
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size); const chain={};
  Interceptor.attach(base.add(SM3),{onEnter(){ const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8),32); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV) chain[tid]=Array.from(inp); else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); } else return;
    const a=chain[tid],L=a.length; if(L<9) return; let bl=0; for(let i=L-8;i<L;i++) bl=bl*256+a[i]; const mlen=bl/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return; if(a[mlen-1]!==0x30||mlen<40){ delete chain[tid]; return; }
    let slot=''; let pr=0; for(let i=mlen-17;i<mlen-1;i++){slot+=('0'+a[i].toString(16)).slice(-2); if(a[i]>=0x20&&a[i]<=0x7e)pr++;}
    if(slot!=='00'.repeat(16)&&pr<12) pool[slot]=1; delete chain[tid];
  }});
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    if(cap>=8) return; let x0=a[0];
    try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; if(x0.sub(base).toInt32()!==ORCH) return; }catch(e){ return; }
    cap++;
    const cand=[]; walk(a[1],cand,0);
    // dedup by hex
    const seen={}; const uniq=cand.filter(c=>{ if(seen[c.hex32])return false; seen[c.hex32]=1; return true; });
    send({t:'psk_cand', prog:'0x'+ORCH.toString(16), x1:a[1].toString(), n:uniq.length, cand:uniq.slice(0,20), poolsz:Object.keys(pool).length});
  }});
  send({t:'info',msg:'psk-find installed (orch 0x1814f0)'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

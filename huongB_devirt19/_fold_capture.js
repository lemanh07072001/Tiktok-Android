// _fold_capture.js — locate the REAL SM3 chaining-state buffer for compression 0x186420 and
// capture (state_in, block, state_out) chains so the fold can be reconstructed + tested offline.
//
// Prior "bit-exact 32/32" compared the x24 regfile which is UNCHANGED (holds pointers) — vacuous
// for the crypto. The true state lives in a heap buffer pointed from x1. We dump every candidate
// buffer at onEnter (state_in + block) and onLeave (state_out) for the first N compressions, plus
// mark orchestrator (0x1814f0) boundaries so hashes can be grouped offline. Offline we find the
// buffer whose call-0 value == SM3 IV (6f168073.. / 7380166f..) and chains state_out[i]==state_in[i+1].
'use strict';
const SO='libmetasec_ov.so';
const VMENTRY=0x52924;
const COMPRESS=0x186420;    // compression program
const ORCH=0x1814f0;        // orchestrator (1 call = 1 full hash)
const CAP=(typeof FOLD_CAP!=='undefined')?FOLD_CAP:200;

function hx(p,n){ try{ const u=new Uint8Array(ptr(p).readByteArray(n)); let s=''; for(let i=0;i<n;i++)s+=('0'+u[i].toString(16)).slice(-2); return s; }catch(e){ return null; } }

let cnt=0, orchSeq=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  const base=m.base, lo=base, hi=base.add(m.size);
  const cAddr=base.add(COMPRESS), oAddr=base.add(ORCH);
  send({t:'info',msg:'fold-capture installed base='+base+' cap='+CAP});
  Interceptor.attach(base.add(VMENTRY),{
    onEnter(a){
      let x0=a[0];
      try{ if(x0.compare(lo)<0||x0.compare(hi)>=0) return; }catch(e){ return; }
      if(x0.equals(oAddr)){ orchSeq++; send({t:'orch', seq:orchSeq}); return; }
      if(!x0.equals(cAddr)) return;
      if(cnt>=CAP){ return; }
      const idx=cnt++;
      const x1=a[1];
      this.rec=true; this.idx=idx; this.orch=orchSeq; this.x1=x1; this.x2=a[2]; this.x4=a[4];
      // snapshot input buffers: x1 head (6 ptrs + inline 48B), each pointer's target 128B, x2/x4 regions
      const enter={ head:hx(x1,0x60), d:{}, x2:hx(a[2],0x40), x4:hx(a[4],0x80) };
      for(let i=0;i<6;i++){ try{ const q=ptr(x1).add(i*8).readPointer(); enter.d['q'+i]=hx(q,0x80); }catch(e){ enter.d['q'+i]=null; } }
      this.enter=enter;
    },
    onLeave(){
      if(!this.rec) return;
      const x1=this.x1;
      const leave={ head:hx(x1,0x60), d:{}, x2:hx(this.x2,0x40), x4:hx(this.x4,0x80) };
      for(let i=0;i<6;i++){ try{ const q=ptr(x1).add(i*8).readPointer(); leave.d['q'+i]=hx(q,0x80); }catch(e){ leave.d['q'+i]=null; } }
      send({t:'call', idx:this.idx, orch:this.orch, enter:this.enter, leave:leave});
    }
  });
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const dl=Module.findGlobalExportByName('android_dlopen_ext'); Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){ if(this.p&&this.p.indexOf(SO)>=0) install(); }}); }

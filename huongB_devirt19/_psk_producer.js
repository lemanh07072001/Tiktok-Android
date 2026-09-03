// _psk_producer.js — find the VM program that PRODUCES the PSK (b2a9d40c...). Hook interp 0x52924;
// for each invocation, check if PSK appears in x4 OUTPUT (deref) vs x1 INPUT. Producer = program where
// PSK is in OUTPUT but NOT in input (it created it). Also log timing + prog to find the generator.
'use strict';
const SO='libmetasec_ov.so', VMENTRY=0x52924;
const PSK16='b2a9d40c622aedce93a5e22f03780a67';
function hxbuf(p,n){try{const u=new Uint8Array(ptr(p).readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function hasPSK(p){ // check p + 2-level derefs for PSK16
  try{ const h=hxbuf(p,256); if(h && h.indexOf(PSK16)>=0) return true;
    for(let i=0;i<8;i++){ let q; try{ q=ptr(p).add(i*8).readPointer(); }catch(e){ break; }
      const h2=hxbuf(q,128); if(h2 && h2.indexOf(PSK16)>=0) return true; } }catch(e){}
  return false;
}
const t0=Date.now(); let cap=0; const seenProg={};
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; const base=m.base, lo=base, hi=base.add(m.size);
  Interceptor.attach(base.add(VMENTRY),{onEnter(a){
    let off;
    try{ const x0=a[0]; if(x0.compare(lo)<0||x0.compare(hi)>=0) return; off=x0.sub(base).toInt32(); }catch(e){ return; }
    // LIGHT: only heavy-check the FIRST few invocations of each distinct program
    const cntKey='c_'+off; seenProg[cntKey]=(seenProg[cntKey]||0)+1;
    if(seenProg[cntKey]>3) return;   // check each program at most 3x
    const inHas = hasPSK(a[1]);
    this.off=off; this.inHas=inHas; this.x4=a[4];
  }, onLeave(){
    if(this.off===undefined) return;
    const outHas = hasPSK(this.x4);
    const prog='0x'+this.off.toString(16);
    if(outHas && !this.inHas && !seenProg['P_'+prog]){ seenProg['P_'+prog]=1;
      send({t:'producer', prog:prog, ms:Date.now()-t0, note:'PSK in OUTPUT not INPUT'});
    } else if(outHas && !seenProg['T_'+prog]){ seenProg['T_'+prog]=1;
      send({t:'touches', prog:prog, ms:Date.now()-t0, inHas:this.inHas});
    }
  }});
  send({t:'info',msg:'psk-producer installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

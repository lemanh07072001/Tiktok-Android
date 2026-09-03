'use strict';
const SO='libmetasec_ov.so';
const SM3=0xa0748;
const IV='6f168073b9b21449d742241700068ada';  // first 16B of standard IV
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function inst(base){
  if(installed)return;installed=true;
  const chain={};let done=0;
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId;let stFull,st,inp;
    try{stFull=hx(this.context.x0.add(8).readByteArray(32));inp=new Uint8Array(this.context.x1.readByteArray(64));}catch(e){return;}
    st=stFull.slice(0,32);
    if(st===IV){ if(chain[tid]&&chain[tid].length){emit(tid);} chain[tid]=Array.from(inp); }
    else if(chain[tid]){ for(let i=0;i<64;i++)chain[tid].push(inp[i]); }
  }});
  function emit(tid){
    const a=chain[tid];if(!a||a.length<9)return;
    // The message is all accumulated blocks. Last block has padding.
    // Just dump the raw accumulated bytes (ascii + len) — don't try to strip padding.
    const L=a.length;
    if(done>=50)return;done++;
    let ascii='';for(let i=0;i<Math.min(L,100);i++)ascii+=(a[i]>=32&&a[i]<127)?String.fromCharCode(a[i]):'.';
    send({t:'RAW',blocks:L/64,len:L,ascii:ascii});
  }
  // flush periodically
  setInterval(function(){for(const tid in chain){if(chain[tid]&&chain[tid].length)emit(tid);}},2000);
  send({t:'info',msg:'sm3all installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

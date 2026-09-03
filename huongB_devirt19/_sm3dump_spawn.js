'use strict';
const SO='libmetasec_ov.so';
const SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function inst(base){
  if(installed)return;installed=true;
  const chain={};let total=0;
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId;let st,inp;
    try{st=hx(this.context.x0.add(8).readByteArray(32));inp=new Uint8Array(this.context.x1.readByteArray(64));}catch(e){return;}
    if(st===IV_LE)chain[tid]=Array.from(inp);
    else if(chain[tid]){for(let i=0;i<64;i++)chain[tid].push(inp[i]);}
    else return;
    const a=chain[tid],L=a.length;if(L<9)return;
    let bl=0;for(let i=L-8;i<L;i++)bl=bl*256+a[i];
    const ml=bl/8;
    if(!(ml>0&&ml<L)||a[ml]!==0x80)return;
    total++;
    if(total<=60){
      let ascii='';for(let i=0;i<Math.min(ml,60);i++)ascii+=(a[i]>=32&&a[i]<127)?String.fromCharCode(a[i]):'.';
      let tail='';for(let i=Math.max(0,ml-20);i<ml;i++)tail+=('0'+a[i].toString(16)).slice(-2);
      send({t:'MSG',mlen:ml,last:a[ml-1],head:ascii,tail:tail});
    }
    delete chain[tid];
  }});
  send({t:'info',msg:'sm3dump-spawn installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

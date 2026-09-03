'use strict';
const SO='libmetasec_ov.so';
const SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function inst(base){
  if(installed)return;installed=true;
  const md5log=[];
  Interceptor.attach(base.add(0x15b594),{
    onEnter(){const c=this.context;const len=c.x1.toInt32();this.len=len;this.out=c.x2;this.inp=(len>=0&&len<8192)?hx(c.x0,Math.min(len,4096)):null;},
    onLeave(){if(this.inp!==null){md5log.push({out:hx(this.out,16),inhex:this.inp,len:this.len});if(md5log.length>800)md5log.shift();}}
  });
  const chain={};let zc=0,nzc=0;
  Interceptor.attach(base.add(SM3),{onEnter(){
    const tid=this.threadId;let st,inp;
    try{st=hx(this.context.x0.add(8).readByteArray(32));inp=new Uint8Array(this.context.x1.readByteArray(64));}catch(e){return;}
    if(st===IV_LE)chain[tid]=Array.from(inp);
    else if(chain[tid]){for(let i=0;i<64;i++)chain[tid].push(inp[i]);}
    else return;
    const a=chain[tid],L=a.length;if(L<9)return;
    let bl=0;for(let i=L-8;i<L;i++)bl=bl*256+a[i];
    const ml=bl/8;
    if(!(ml>16&&ml<L)||a[ml]!==0x80)return;
    if(a[ml-1]!==0x30||ml<200){delete chain[tid];return;}
    let slot='';for(let i=ml-17;i<ml-1;i++)slot+=('0'+a[i].toString(16)).slice(-2);
    if(slot==='00000000000000000000000000000000')zc++;
    else{nzc++;let found=null;
      for(let k=md5log.length-1;k>=0;k--){if(md5log[k].out===slot){found=md5log[k];break;}}
      let pre=null;if(found){const raw=Array.from(bytes(found.inhex)).slice(0,found.len);}
      send({t:'NZ',slot16:slot,md5match:found});}
    delete chain[tid];
  }});
  setInterval(function(){send({t:'HB',zero:zc,nonzero:nzc});},2000);
  send({t:'info',msg:'vlong-spawn installed base='+base});
}
function bytes(h){const a=new Uint8Array(h.length/2);for(let i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

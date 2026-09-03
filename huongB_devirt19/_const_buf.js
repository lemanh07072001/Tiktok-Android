'use strict';
// Find session-constant binary buffers (PSK candidate) via memcpy hook.
// PSK = 16-32B binary, appears repeatedly identical, high entropy, not ASCII query text.
const SO='libmetasec_ov.so';
let installed=false;
function u8(p,n){try{return new Uint8Array(p.readByteArray(n));}catch(e){return null;}}
function hx(a){let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}
function entropy(a){const c={};for(const b of a)c[b]=(c[b]||0)+1;let e=0;for(const k in c){const p=c[k]/a.length;e-=p*Math.log2(p);}return e;}
function isAsciiQuery(a){let pr=0;for(const b of a)if(b>=32&&b<127)pr++;return pr>=a.length*0.85;}
function inst(base){
  if(installed)return;installed=true;
  const counts={};  // hexbuf -> count
  const memcpy=Module.findGlobalExportByName('memcpy');
  Interceptor.attach(memcpy,{
    onEnter(a){
      const n=a[2].toInt32();
      if(n<16||n>32)return;
      const buf=u8(a[1],n);
      if(!buf)return;
      if(isAsciiQuery(buf))return;        // skip query text
      if(entropy(buf)<3.0)return;          // skip low-entropy (zeros/padding)
      const h=hx(buf);
      counts[h]=(counts[h]||0)+1;
    }
  });
  setInterval(function(){
    // report buffers seen >=3 times (session-constant = PSK candidate)
    const rep=[];
    for(const h in counts){ if(counts[h]>=3) rep.push([h,counts[h]]); }
    rep.sort((a,b)=>b[1]-a[1]);
    send({t:'CONST',top:rep.slice(0,15)});
  },3000);
  send({t:'info',msg:'const buf finder installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

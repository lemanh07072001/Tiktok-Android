'use strict';
const SO='libmetasec_ov.so';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.';return s;}catch(e){return'ERR';}}
function inst(base){
  if(installed)return;installed=true;
  let n=0;
  // AES round/block fn 0x159618: typically (state, key) or (in, out, key)
  Interceptor.attach(base.add(0x159618),{
    onEnter(){ if(n>=40)return; const c=this.context;
      this.x0=c.x0;this.x1=c.x1;this.x2=c.x2;
      this.in0=hx(c.x0,16); this.in1=hx(c.x1,16);
    },
    onLeave(){ if(n>=40)return; n++;
      // after: x0 or x1 holds output block
      send({t:'AES',n:n,
        x0:this.x0.toString(16),x1:this.x1.toString(16),
        in0:this.in0, in1:this.in1,
        out0:hx(this.x0,16), out1:hx(this.x1,16),
        out0_asc:asc(this.x0,16), out1_asc:asc(this.x1,16)});
    }
  });
  send({t:'info',msg:'aes hook installed base='+base});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

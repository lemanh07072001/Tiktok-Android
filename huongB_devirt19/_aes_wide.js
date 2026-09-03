'use strict';
const SO='libmetasec_ov.so';
let installed=false;
function hx(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return'ERR';}}
function looksText(p,n){try{const u=new Uint8Array(p.readByteArray(n));let pr=0;for(let i=0;i<u.length;i++)if(u[i]>=32&&u[i]<127)pr++;return pr>=n*0.7;}catch(e){return false;}}
function asc(p,n){try{const u=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<u.length;i++)s+=(u[i]>=32&&u[i]<127)?String.fromCharCode(u[i]):'.';return s;}catch(e){return'';}}
function inst(base){
  if(installed)return;installed=true;
  let hits=0;
  Interceptor.attach(base.add(0x159618),{
    onEnter(){ this.x0=this.context.x0; this.x1=this.context.x1; this.x2=this.context.x2; },
    onLeave(){
      // check all 3 pointer args for text output (plaintext PSK/keva/json)
      for(const [nm,p] of [['x0',this.x0],['x1',this.x1],['x2',this.x2]]){
        if(!p||p.isNull())continue;
        if(looksText(p,32)){
          const a=asc(p,64);
          // filter meaningful: contains json/keva/{ or long alnum
          if(a.indexOf('{')>=0||a.indexOf('keva')>=0||a.indexOf('psk')>=0||a.indexOf('"')>=0||/[a-zA-Z0-9]{12}/.test(a)){
            hits++;
            if(hits<=30) send({t:'TEXT',reg:nm,ascii:a,hex:hx(p,64)});
          }
        }
      }
    }
  });
  send({t:'info',msg:'aes wide installed'});
}
const m=Process.findModuleByName(SO);
if(m)inst(m.base);
else{const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0){const mm=Process.findModuleByName(SO);if(mm)inst(mm.base);}}});}

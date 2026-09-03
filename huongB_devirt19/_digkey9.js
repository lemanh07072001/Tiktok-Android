'use strict';
// _digkey9 — same-session oracle: (secret @ctx+0x10, all ctx string-fields, message) + resulting hexdigest (F1)
const SO='libmetasec_ov.so';
const PROD=0x879d8, F1=0x151d40;
let base=null,lo=null,hi=null;
function inMod(p){try{return p.compare(lo)>=0&&p.compare(hi)<0;}catch(e){return false;}}
function readable(p){try{p.readU8();return true;}catch(e){return false;}}
function cstr(p,max){ // read printable C-string, stop at NUL or nonprintable
  try{const a=new Uint8Array(p.readByteArray(max||128));let s='';for(let i=0;i<a.length;i++){const c=a[i];if(c===0)break;if(c<32||c>126){s='';break;}s+=String.fromCharCode(c);}return s;}catch(e){return '';}
}
function hexbuf(p,n){try{const a=new Uint8Array(p.readByteArray(n));let s='';for(let i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
// walk ctx: for each aligned qword that's a readable heap ptr, try to read a printable string at *ptr
function ctxStrings(x0){
  const out=[];
  for(let off=0;off<0x200;off+=8){
    let v; try{v=x0.add(off).readPointer();}catch(e){continue;}
    if(inMod(v)||!readable(v))continue;
    const s=cstr(v,200);
    if(s&&s.length>=3) out.push({off:off,p:v.toString(),s:s});
  }
  return out;
}
let np=0; const MAX=6; const prods=[]; const f1s=[];
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info',base:base.toString()});
  Interceptor.attach(base.add(PROD),{
    onEnter(a){
      if(np>=MAX)return;
      const c=this.context;
      const sel=parseInt(c.x1.toString())&0xffffffff;
      let secret=''; try{secret=cstr(c.x0.add(0x10).readPointer(),128);}catch(e){}
      const strs=ctxStrings(c.x0);
      const rec={i:np,sel:sel,secret:secret,strs:strs,ctx:hexbuf(c.x0,0x120)};
      prods.push(rec); np++;
      send({t:'PROD',i:rec.i,sel:sel,secret:secret,nstr:strs.length});
      if(np>=MAX){send({t:'PRODDUMP',prods:prods,f1s:f1s});}
    }
  });
  Interceptor.attach(base.add(F1),{
    onEnter(a){
      if(f1s.length>=40)return;
      const c=this.context;
      // capture printable strings from x0,x1,x2,x3 targets (uppercase hexdigest is among them)
      const g=(r)=>{try{return cstr(r,80);}catch(e){return '';}};
      const rec={x0:g(c.x0),x1:g(c.x1),x2:g(c.x2),x3:g(c.x3),
                 x2v:c.x2.toString(),x1v:c.x1.toString()};
      // also: x0 may be std::string dest — try long-mode data
      f1s.push(rec);
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO))install();
else{const f=()=>{if(Process.findModuleByName(SO))install();else setTimeout(f,200);};setTimeout(f,400);}
setInterval(()=>send({t:'mon',np:np,nf1:f1s.length}),4000);

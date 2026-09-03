'use strict';
const A_HEAD='c02f250f86cc4f19';           // A[0:8]
const A_FULL='c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163';
const LENS={16:1,24:1,32:1,36:1,48:1,64:1,68:1};
let base=null, nHit=0; const MAX=8;
function head8(p){ try{ const b=new Uint8Array(p.readByteArray(8)); let s='';
  for(let i=0;i<8;i++)s+=('0'+b[i].toString(16)).slice(-2); return s; }catch(e){return null;} }
function hexN(p,n){ try{ const b=new Uint8Array(p.readByteArray(n)); let s='';
  for(let i=0;i<n;i++)s+=('0'+b[i].toString(16)).slice(-2); return s; }catch(e){return null;} }
function classify(p){
  try{ const r=Process.findRangeByAddress(p);
    if(!r) return {range:null};
    let modoff=null; const m=Process.findModuleByAddress(p);
    if(m) modoff=m.name+'+0x'+p.sub(m.base).toString(16);
    return {base:r.base.toString(),size:r.size,prot:r.protection,
            file:(r.file?r.file.path:null),foff:(r.file?r.file.offset:null),mod:modoff}; }
  catch(e){ return {err:''+e}; }
}
function onCopy(dst,src,len,who){
  if(nHit>=MAX)return;
  if(!LENS[len])return;
  const h=head8(src); if(h!==A_HEAD)return;
  nHit++;
  send({t:'ASRC',who:who,len:len,
    src:src.toString(), dst:dst.toString(),
    srcHex:hexN(src, Math.min(len,68)),
    srcRange:classify(src), dstRange:classify(dst)});
}
function hookExp(name){
  try{ const a=Module.getExportByName('libc.so',name); if(!a)return;
    Interceptor.attach(a,{ onEnter(ar){
      try{ onCopy(this.context.x0,this.context.x1,this.context.x2.toInt32()&0xffffffff,name); }catch(e){}
    }});
    send({t:'hooked',name:name});
  }catch(e){ send({t:'hookfail',name:name,e:''+e}); }
}
function install(){
  const m=Process.findModuleByName('libmetasec_ov.so'); if(m){base=m.base;}
  ['memcpy','memmove','__memcpy_chk','__memmove_chk'].forEach(hookExp);
  send({t:'ready'}); return true;
}
install();
setInterval(()=>send({t:'mon',nHit:nHit}),5000);

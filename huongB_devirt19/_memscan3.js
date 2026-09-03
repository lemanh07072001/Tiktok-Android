'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
const A_HEX='c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163';
const S16_HEX='6c109094bc9ab89e050fbd3e2ca6b99e';
let base=null;
let armed=false;      // A đã thấy live -> cho phép quét
let bufInfo=null;     // phân loại range của buffer x0
let scanned=false;

function hexOf(p,n){ try{ const b=new Uint8Array(p.readByteArray(n)); let s='';
  for(let i=0;i<n;i++)s+=('0'+b[i].toString(16)).slice(-2); return s; }catch(e){return null;} }

function classify(addr){
  try{ const r=Process.findRangeByAddress(ptr(addr));
    if(!r) return {addr:addr, range:null};
    return {addr:addr, base:r.base.toString(), size:r.size, prot:r.protection,
            file:(r.file?r.file.path:null), foff:(r.file?r.file.offset:null)}; }
  catch(e){ return {addr:addr, err:''+e}; }
}

function scanFor(hexpat,label){
  const ranges=Process.enumerateRanges('rw-').concat(Process.enumerateRanges('r--'));
  let hits=0; const out=[]; let n=0;
  for(const r of ranges){ n++;
    try{ const found=Memory.scanSync(r.base,r.size,hexpat);
      for(const f of found){ hits++;
        out.push({addr:f.address.toString(), prot:r.protection,
          file:(r.file?r.file.path:null), foff:(r.file?r.file.offset:null)});
        if(hits>=20)break; } }catch(e){}
    if(hits>=20)break; }
  send({t:'SCAN',label:label,hits:hits,nranges:n,out:out});
}

function install(){
  const m=Process.findModuleByName(SO); if(!m)return false;
  base=m.base; send({t:'info',msg:'loaded',base:base.toString()});
  Interceptor.attach(base.add(DRV),{ onEnter(a){
    if(armed)return;
    const len=this.context.x1.toInt32()&0xffffffff;
    if(len<68)return;
    const x0=this.context.x0;
    const pre=hexOf(x0,32);
    if(pre===A_HEX){
      armed=true;
      bufInfo=classify(x0.toString());
      send({t:'BUF_HIT',len:len,buf:bufInfo});
    }
  }});
  send({t:'ready'}); return true;
}

if(Process.findModuleByName(SO))install();
else { const t=()=>{ if(Process.findModuleByName(SO))install(); else setTimeout(t,200); }; setTimeout(t,400); }

// Poller: khi A đã live thì quét mọi range tìm bản sao bền
setInterval(()=>{
  if(armed && !scanned){ scanned=true;
    send({t:'scanning'});
    scanFor(A_HEX,'device_key_A');
    scanFor(S16_HEX,'slot16_privacy');
    send({t:'done'});
  }
  send({t:'mon',armed:armed,scanned:scanned});
},3000);

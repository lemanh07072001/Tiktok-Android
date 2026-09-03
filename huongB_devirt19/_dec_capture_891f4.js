'use strict';
// Capture slot16 at the confirmed hex_to_bytes decoder 0x891f4.
// AAPCS64: x8 = output struct (sret). Output: [x8+4]=nbytes, [x8+8]=ptr(data).
// Input: x0 = input struct; [x0+4]=hex length. Filter outlen==16 to isolate slot16.
const SO='libmetasec_ov.so';
const OFF=0x891f4;
const MAX=60;
let base=null, n=0;

function dump(p,len){ try{ return hex(ptr(p).readByteArray(len)); }catch(e){ return null; } }
function hex(ab){ if(!ab) return null; const u=new Uint8Array(ab); let s='';
  for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
function asAscii(hx){ if(!hx) return null; let s=''; for(let i=0;i<hx.length;i+=2){
  const b=parseInt(hx.substr(i,2),16); if(b===0) break;
  s += (b>=32&&b<127)? String.fromCharCode(b) : '.'; } return s; }

function install(){
  const m=Process.findModuleByName(SO);
  if(!m) return false;
  base=m.base;
  send({t:'info', base:base.toString(), size:m.size});
  Interceptor.attach(base.add(OFF), {
    onEnter(a){
      const c=this.context;
      this._x8=c.x8; this._x0=c.x0;
      try{ this._lr = c.lr.sub(base).toString(16); }catch(e){ this._lr=null; }
      try{ this._inlen = ptr(c.x0).add(4).readU32(); }catch(e){ this._inlen=-1; }
      this._inStruct = dump(c.x0, 0x20);
      // hex chars may be inline at x0 or via ptr at [x0+8]
      let dptr=null; try{ dptr=ptr(c.x0).add(8).readPointer(); }catch(e){}
      this._inViaPtr = dptr? dump(dptr, 0x48) : null;
      this._inInline = dump(c.x0, 0x28);
    },
    onLeave(rv){
      let outlen=-1, dptr=null, outbytes=null;
      try{ outlen=ptr(this._x8).add(4).readU32(); }catch(e){}
      try{ dptr=ptr(this._x8).add(8).readPointer(); }catch(e){}
      if(dptr && outlen>0 && outlen<=64){ outbytes=dump(dptr, outlen); }
      if(outlen===16 && n<MAX){
        n++;
        const inHex = this._inViaPtr || this._inInline;
        send({t:'DEC', seq:n, lr:this._lr, inlen:this._inlen,
              in_ascii: asAscii(inHex), in_via_ptr:this._inViaPtr,
              in_inline:this._inInline, in_struct:this._inStruct,
              outlen:outlen, slot16:outbytes});
      }
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,150); }; setTimeout(t,300); }
setInterval(()=>send({t:'mon', n:n}), 4000);

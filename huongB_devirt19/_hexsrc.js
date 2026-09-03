/*
 * _hexsrc.js — hook hex_to_bytes @0x891f4. Read x0 = source hex-string object,
 * layout [0]=cap(int),[4]=len(int),[8]=dataptr (same struct as grow-helper).
 * Then at SM3-driver 0x9fd98 confirm P(16B)==unhex(src). Prove slot16=unhex(hex).
 */
'use strict';
const SO='libmetasec_ov.so';
const OFF_HEX=0x891f4, OFF_DRIVER=0x9fd98;
let base=null, lo=null, hi=null;
let pending=[];           // recent {hexstr, hexlen}
let nHex=0, nDrv=0, hits=0; const MAXHIT=12;

function inSelf(p){ try{ return p.compare(lo)>=0 && p.compare(hi)<0; }catch(e){ return false; } }
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
function readStr(objptr){
  // returns {len, data} or null
  try{
    const len=objptr.add(4).readU32();
    if(len<0||len>4096) return null;
    // try heap layout: data at [obj+8]
    let dptr=objptr.add(8).readPointer();
    let bytes;
    try{ bytes=dptr.readByteArray(len); if(bytes) return {len:len, ascii:asciiOf(bytes), hexdata:hx(bytes)}; }catch(e){}
    // fallback: inline (SSO) — data starts at obj+8 directly
    try{ bytes=objptr.add(8).readByteArray(len); if(bytes) return {len:len, ascii:asciiOf(bytes), hexdata:hx(bytes)}; }catch(e){}
  }catch(e){}
  return null;
}
function asciiOf(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++){ const c=u[i]; s+=(c>=32&&c<127)?String.fromCharCode(c):'.'; } return s; }

function install(){
  const m=Process.findModuleByName(SO); if(!m) return false;
  base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});

  Interceptor.attach(base.add(OFF_HEX),{
    onEnter(args){
      const src=this.context.x0;
      const s=readStr(src);
      if(s){ pending.push({s:s, t:Date.now()}); if(pending.length>32) pending.shift(); nHex++;
        if(nHex<=40) send({t:'HEXSRC', len:s.len, ascii:s.ascii, data:s.hexdata}); }
    }
  });

  Interceptor.attach(base.add(OFF_DRIVER),{
    onEnter(args){
      if(hits>=MAXHIT) return;
      let len; try{ len=parseInt(this.context.x1.toString())&0xffffffff; }catch(e){ return; }
      if(len!==16) return;
      const P=this.context.x0;
      let val; try{ val=hx(P.readByteArray(16)); }catch(e){ return; }
      if(/^0+$/.test(val)) return;
      nDrv++; hits++;
      // find most recent pending hexsrc whose unhex == val
      let match=null;
      for(let i=pending.length-1;i>=0;i--){
        const a=pending[i].s.ascii.replace(/\./g,'');
        if(a.toLowerCase()===val.toLowerCase()){ match=pending[i].s; break; }
      }
      send({t:'DRV', slot16:val, matchAscii: match?match.ascii:null, matchLen: match?match.len:null,
            lastAscii: pending.length?pending[pending.length-1].s.ascii:null});
    }
  });
  send({t:'ready'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else { const t=()=>{ if(Process.findModuleByName(SO)) install(); else setTimeout(t,200); }; setTimeout(t,300); }
setInterval(function(){ send({t:'mon', nHex:nHex, nDrv:nDrv, hits:hits}); }, 3000);

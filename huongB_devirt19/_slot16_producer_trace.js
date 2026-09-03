// _slot16_producer_trace.js — target a KNOWN recurring pool slot16, hook memcpy/memmove
// gated on len==16, and when src[0:16]==target report src addr + region + native backtrace.
// The copy INTO the SM3 query buffer reveals the pool source; the backtrace reveals the copier.
'use strict';
const TARGETS=['b8591fcb8d86ff40ed3989462a588bf1','9ae50e6bfa15208a2bc1ec3fa91835cc',
               'cb12155b4933d1500308499e4fcb6694','46c03b52742b3f2615a3abdf1636b754'];
const TSET={}; TARGETS.forEach(t=>TSET[t]=1);
function hx16(p){try{const u=new Uint8Array(ptr(p).readByteArray(16));let s='';for(let i=0;i<16;i++)s+=('0'+u[i].toString(16)).slice(-2);return s;}catch(e){return null;}}
function region(a){
  try{ const m=Process.findModuleByAddress(a); if(m) return m.name+'+0x'+a.sub(m.base).toString(16); }catch(e){}
  try{ const r=Process.findRangeByAddress(a); if(r) return (r.file?r.file.path:'[anon]')+' '+r.protection; }catch(e){}
  return 'anon?';
}
const seen={}; let cnt=0;
function onCopy(dst,src,len){
  if(len<16||len>48) return;
  const s=hx16(src); if(!s||!TSET[s]) return;
  const key=s+'@'+src;
  if(seen[key]||cnt>=8) return; seen[key]=1; cnt++;
  let bt=[];
  try{ bt=Thread.backtrace(this && this.context ? this.context : null, Backtracer.ACCURATE)
        .slice(0,8).map(a=>a+' '+region(a)); }catch(e){}
  send({t:'prod', slot16:s, src:src.toString(), src_region:region(src), dst:dst.toString(), dst_region:region(dst), len:len, bt:bt});
}
function hookCopy(name){
  const p=Module.findGlobalExportByName(name); if(!p) return;
  Interceptor.attach(p,{onEnter(a){ try{ onCopy.call(this, a[0], a[1], a[2].toInt32()); }catch(e){} }});
}
hookCopy('memcpy'); hookCopy('memmove'); hookCopy('__memcpy_chk'); hookCopy('__memmove_chk');
send({t:'info',msg:'producer-trace installed len16-48 targets='+TARGETS.length});

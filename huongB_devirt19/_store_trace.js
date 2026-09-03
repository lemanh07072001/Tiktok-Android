'use strict';
// STORE-TRACE ORACLE — file-correlated. Attach at splash.
//  * libc open/openat/read/pread hooks (present from splash, NO race) capture
//    exactly WHICH store file is read and its RAW ciphertext bytes -> FILERD.
//  * dlopen-arm installs libmetasec AES hooks: EINIT (0x159d60) logs EVERY
//    distinct key+iv (the master key inventory), KSCH userKeys, CT in/out.
// Offline: for each FILERD ciphertext, brute every EINIT (key,iv) across AES
//  modes -> the store key/mode is whichever yields structured plaintext.
// ATTACH-ONLY. No re-register.
var MOD='libmetasec_ov.so';
var OFF={ KSCH:0x1591bc, EINIT:0x159d60,
          BDEC:0x15997c, BDEC2:0x159618, CBCD:0x159f58, CBCE:0x159de4, BENC:0x159d1c };
var STORE_RE=/\/\.msdata\/|\/mssdk\/|\/ov\/\.ms|\.ms(s|p|f3|fs|f)?[_.]/;
var installed=false, preloaded=false;
var keys={}, einits={}, cts={}, log=[];
var lastKey={}, lastIV={};
var fdmap={}, filerd=[], fseen={};

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s='';
  for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function looksPtr(p){ try{ return !p.isNull() && p.compare(ptr('0x10000'))>0 && p.compare(ptr('0x8000000000'))<0; }catch(e){return false;} }
function rd(p,n){ try{ if(!looksPtr(p)) return null; return b2h(p.readByteArray(n)); }catch(e){return null;} }
function kbnorm(v){ return (v===16||v===24||v===32)?v:16; }

// ---------- libc file hooks (global, from splash) ----------
function hookFile(){
  var openat=Module.findGlobalExportByName?Module.findGlobalExportByName('openat'):null;
  var openp =Module.findGlobalExportByName?Module.findGlobalExportByName('open'):null;
  var readp =Module.findGlobalExportByName?Module.findGlobalExportByName('read'):null;
  var preadp=Module.findGlobalExportByName?Module.findGlobalExportByName('pread'):null;
  if(!preadp){ try{preadp=Module.findGlobalExportByName('pread64');}catch(e){} }
  if(!readp){  try{readp =Module.findGlobalExportByName('read');}catch(e){} }
  if(openat){ Interceptor.attach(openat,{
    onEnter:function(a){ try{this.path=a[1].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(r){ var fd=r.toInt32(); if(fd>=0 && this.path && STORE_RE.test(this.path)) fdmap[fd]=this.path; }
  }); }
  if(openp){ Interceptor.attach(openp,{
    onEnter:function(a){ try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(r){ var fd=r.toInt32(); if(fd>=0 && this.path && STORE_RE.test(this.path)) fdmap[fd]=this.path; }
  }); }
  function grab(fd,buf,ret){
    var path=fdmap[fd]; if(!path||ret<=0) return;
    var n=ret>2048?2048:ret;
    var bytes=rd(buf,n); if(!bytes) return;
    var id=path+'|'+ret+'|'+bytes.slice(0,32);
    if(fseen[id]) return; fseen[id]=1;
    var ev={path:path, ret:ret, bytes:bytes};
    filerd.push(ev); send({tag:'FILERD', path:path, ret:ret, head:bytes.slice(0,64)});
  }
  if(readp){ Interceptor.attach(readp,{
    onEnter:function(a){ this.fd=a[0].toInt32(); this.buf=a[1]; },
    onLeave:function(r){ grab(this.fd,this.buf,r.toInt32()); }
  }); }
  if(preadp){ Interceptor.attach(preadp,{
    onEnter:function(a){ this.fd=a[0].toInt32(); this.buf=a[1]; },
    onLeave:function(r){ grab(this.fd,this.buf,r.toInt32()); }
  }); }
  send({tag:'FILEHOOK'});
}

// ---------- libmetasec AES hooks ----------
function recKey(tid,keyhex,kb){ if(!keyhex) return; var k=kb+':'+keyhex;
  if(!keys[k]){ keys[k]=1; send({tag:'KEY',kb:kb,key:keyhex}); } else keys[k]++;
  lastKey[tid]={key:keyhex,kb:kb}; }
function recEinit(tid,keyhex,kb,ivhex){ if(keyhex) lastKey[tid]={key:keyhex,kb:kb}; if(ivhex) lastIV[tid]=ivhex;
  var id=kb+':'+(keyhex||'')+':'+(ivhex||'');
  if(!einits[id]){ einits[id]=1; send({tag:'EINIT',kb:kb,key:keyhex,iv:ivhex}); } else einits[id]++; }
function recCT(tid,prim,inhex,outhex,len){ var lk=lastKey[tid]||{}, iv=lastIV[tid]||null;
  var id=prim+'|'+(inhex?inhex.slice(0,32):'')+'|'+(lk.key||''); if(cts[id]){cts[id]++;return;} cts[id]=1;
  var ev={prim:prim,key:lk.key||null,kb:lk.kb||null,iv:iv,inhex:inhex,outhex:outhex,len:len};
  log.push(ev); send({tag:'CT',ev:ev}); }

function install(base){
  if(installed) return; installed=true; var A=function(o){return base.add(o);};
  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    recKey(Process.getCurrentThreadId(), rd(a[1],kb), kb); }});
  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    recEinit(Process.getCurrentThreadId(), rd(a[1],kb), kb, rd(a[3],16)); }});
  function hookCBC(off,name){ Interceptor.attach(A(off),{
    onEnter:function(a){ this.tid=Process.getCurrentThreadId(); this.in=a[1]; this.out=a[2];
      this.len=(function(){try{return a[3].toInt32();}catch(e){return -1;}})(); },
    onLeave:function(){ var n=(this.len>0&&this.len<=256)?this.len:64; var ih=rd(this.in,n), oh=rd(this.out,n);
      if(ih||oh) recCT(this.tid,name,ih,oh,this.len); } }); }
  hookCBC(OFF.CBCD,'CBCD'); hookCBC(OFF.CBCE,'CBCE');
  function hookBLK(off,name){ Interceptor.attach(A(off),{
    onEnter:function(a){ this.tid=Process.getCurrentThreadId(); this.in=a[1]; this.out=a[2]; },
    onLeave:function(){ var ih=rd(this.in,16), oh=rd(this.out,16); if(ih||oh) recCT(this.tid,name,ih,oh,16); } }); }
  hookBLK(OFF.BDEC,'BDEC'); hookBLK(OFF.BDEC2,'BDEC2'); hookBLK(OFF.BENC,'BENC');
  send({tag:'READY', base:base.toString(), preloaded:preloaded});
}

(function(){
  try{ hookFile(); }catch(e){ send({tag:'FILEHOOK_ERR',e:String(e)}); }
  var m=null; Process.enumerateModules().forEach(function(x){ if(x.name===MOD) m=x; });
  if(m){ preloaded=true; install(m.base); return; }
  ['android_dlopen_ext','dlopen','__loader_dlopen'].forEach(function(fn){
    var p=Module.findGlobalExportByName?Module.findGlobalExportByName(fn):null;
    if(!p){ try{p=Module.getGlobalExportByName(fn);}catch(e){} }
    if(p){ Interceptor.attach(p,{ onLeave:function(){ if(installed) return;
      Process.enumerateModules().forEach(function(x){ if(x.name===MOD) install(x.base); }); }}); }
  });
  send({tag:'WAIT_DLOPEN'});
})();

rpc.exports={
  status:function(){ return {installed:installed, preloaded:preloaded, nfiles:filerd.length,
    nkeys:Object.keys(keys).length, neinit:Object.keys(einits).length, ncts:Object.keys(cts).length}; },
  dump:function(){ return {keys:keys, einits:einits, cts:log, filerd:filerd}; }
};

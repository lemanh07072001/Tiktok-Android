'use strict';
// STORE-TRACE v2 — SPAWN-time, read+write+RDR. Hooks live before ANY init I/O.
var MOD='libmetasec_ov.so';
var OFF={ KSCH:0x1591bc, EINIT:0x159d60, RDR:0xe2df0,
          BDEC:0x15997c, BDEC2:0x159618, CBCD:0x159f58, CBCE:0x159de4, BENC:0x159d1c };
var STORE_RE=/\/\.msdata\/|\/mssdk\/|\/ov\/|\.ms(s|p|f3|fs|f)?[_.]/;
var installed=false, preloaded=false;
var keys={}, einits={}, cts={}, log=[];
var lastKey={}, lastIV={};
var fdmap={}, filerd=[], fseen={};

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s='';
  for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function looksPtr(p){ try{ return !p.isNull() && p.compare(ptr('0x10000'))>0 && p.compare(ptr('0x8000000000'))<0; }catch(e){return false;} }
function rd(p,n){ try{ if(!looksPtr(p)) return null; return b2h(p.readByteArray(n)); }catch(e){return null;} }
function kbnorm(v){ return (v===16||v===24||v===32)?v:16; }
function grabIO(kind,fd,buf,ret){
  var path=fdmap[fd]; if(!path||ret<=0) return;
  var n=ret>4096?4096:ret; var bytes=rd(buf,n); if(!bytes) return;
  var id=kind+'|'+path+'|'+ret+'|'+bytes.slice(0,32);
  if(fseen[id]) return; fseen[id]=1;
  filerd.push({kind:kind,path:path,ret:ret,bytes:bytes});
  send({tag:'FILE'+kind, path:path, ret:ret, head:bytes.slice(0,96)});
}
function hookFile(){
  var E=function(n){ try{return Module.findGlobalExportByName(n);}catch(e){return null;} };
  var openat=E('openat'), openp=E('open'), readp=E('read'), preadp=E('pread')||E('pread64'),
      writep=E('write'), pwritep=E('pwrite')||E('pwrite64');
  function onOpen(idx){ return { onEnter:function(a){ try{this.path=a[idx].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(r){ var fd=r.toInt32(); if(fd>=0&&this.path&&STORE_RE.test(this.path)) fdmap[fd]=this.path; } }; }
  if(openat) Interceptor.attach(openat,onOpen(1));
  if(openp)  Interceptor.attach(openp,onOpen(0));
  if(readp)  Interceptor.attach(readp,{ onEnter:function(a){this.fd=a[0].toInt32();this.buf=a[1];},
    onLeave:function(r){ grabIO('RD',this.fd,this.buf,r.toInt32()); } });
  if(preadp) Interceptor.attach(preadp,{ onEnter:function(a){this.fd=a[0].toInt32();this.buf=a[1];},
    onLeave:function(r){ grabIO('RD',this.fd,this.buf,r.toInt32()); } });
  if(writep) Interceptor.attach(writep,{ onEnter:function(a){ grabIO('WR',a[0].toInt32(),a[1],a[2].toInt32()); } });
  if(pwritep)Interceptor.attach(pwritep,{ onEnter:function(a){ grabIO('WR',a[0].toInt32(),a[1],a[2].toInt32()); } });
  var mmapp=E('mmap')||E('mmap64');
  if(mmapp) Interceptor.attach(mmapp,{
    onEnter:function(a){ this.fd=a[4].toInt32(); this.len=a[1].toInt32(); },
    onLeave:function(r){ var path=fdmap[this.fd]; if(!path) return;
      try{ if(r.isNull()||r.compare(ptr('0xffffffffffffffff'))===0) return; }catch(e){}
      var n=this.len>4096?4096:this.len; var bytes=rd(r,n); if(!bytes) return;
      var id='MMAP|'+path+'|'+this.len+'|'+bytes.slice(0,32);
      if(fseen[id]) return; fseen[id]=1;
      filerd.push({kind:'MMAP',path:path,ret:this.len,bytes:bytes});
      send({tag:'FILEMMAP', path:path, ret:this.len, head:bytes.slice(0,96)}); }});
  send({tag:'FILEHOOK'});
}

function recKey(tid,keyhex,kb){ if(!keyhex) return; var k=kb+':'+keyhex;
  if(!keys[k]){ keys[k]=1; send({tag:'KEY',kb:kb,key:keyhex}); } else keys[k]++;
  lastKey[tid]={key:keyhex,kb:kb}; }
function recEinit(tid,keyhex,kb,ivhex){ if(keyhex) lastKey[tid]={key:keyhex,kb:kb}; if(ivhex) lastIV[tid]=ivhex;
  var id=kb+':'+(keyhex||'')+':'+(ivhex||'');
  if(!einits[id]){ einits[id]=1; send({tag:'EINIT',kb:kb,key:keyhex,iv:ivhex}); } else einits[id]++; }
function recCT(tid,prim,inhex,outhex,len){ var lk=lastKey[tid]||{}, iv=lastIV[tid]||null;
  var id=prim+'|'+(inhex?inhex.slice(0,32):'')+'|'+(lk.key||''); if(cts[id]){cts[id]++;return;} cts[id]=1;
  log.push({prim:prim,key:lk.key||null,kb:lk.kb||null,iv:iv,inhex:inhex,outhex:outhex,len:len}); }

function install(base){
  if(installed) return; installed=true; var A=function(o){return base.add(o);};
  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    recKey(Process.getCurrentThreadId(), rd(a[1],kb), kb); }});
  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    recEinit(Process.getCurrentThreadId(), rd(a[1],kb), kb, rd(a[3],16)); }});
  // RDR direct: log path + output buffer (store reader inside libmetasec)
  Interceptor.attach(A(OFF.RDR),{
    onEnter:function(a){ this.pbuf=a[1]; this.plen=a[2]; try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(){ if(!this.path) return;
      var len=0,buf=null; try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}}
      try{buf=this.pbuf.readPointer();}catch(e){}
      var head=(buf&&len)?rd(buf,Math.min(len,96)):null;
      log.push({prim:'RDR',path:this.path,len:len,head:head});
      send({tag:'RDR', path:this.path, len:len, head:head}); }});
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
    var p=null; try{p=Module.findGlobalExportByName(fn);}catch(e){}
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

'use strict';
// STORE-WRITE oracle v4 — capture the periodic store FLUSH (write path).
// Finding: .ms* files are WRITE-mostly early post-launch (.msp_092 rewritten @09:15).
// Hook full write family (write/pwrite/writev/pwritev/msync/rename) + EINIT/KSCH-all
// + encrypt prims in a window after any store write-open. When a store file is
// written we capture the CIPHERTEXT + the store KEY(EINIT userKey)+IV at that moment.
var MOD='libmetasec_ov.so';
var OFF={ KSCH:0x1591bc, EINIT:0x159d60, RDR:0xe2df0,
          BENC:0x159d1c, CBCE:0x159de4, BDEC:0x15997c, BDEC2:0x159618, CBCD:0x159f58 };
var STORE_RE=/\/\.msdata\/|\/mssdk\/|\/ov\/|\.ms(s|p|f3|fs|f)?[_.]/;
var installed=false, preloaded=false;
var fdmap={}, fseen={}, wlog=[], armUntil=0, log=[];
var keys={}, einits={}, lastKey={}, lastIV={};

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s='';
  for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function looksPtr(p){ try{ return !p.isNull() && p.compare(ptr('0x10000'))>0 && p.compare(ptr('0x8000000000'))<0; }catch(e){return false;} }
function rd(p,n){ try{ if(!looksPtr(p)) return null; return b2h(p.readByteArray(n)); }catch(e){return null;} }
function kbnorm(v){ return (v===16||v===24||v===32)?v:16; }

function grabWrite(kind,fd,bytes,total,extra){
  var path=fdmap[fd]; if(!path) return;
  var id=kind+'|'+path+'|'+total+'|'+(bytes?bytes.slice(0,40):'');
  if(fseen[id]) return; fseen[id]=1;
  armUntil=Date.now()+150;
  wlog.push({kind:kind,path:path,total:total,bytes:bytes,extra:extra||null});
  send({tag:'WRITE', kind:kind, path:path, total:total, head:bytes?bytes.slice(0,128):null, extra:extra||null});
}

function hookIO(){
  var E=function(n){ try{return Module.findGlobalExportByName(n);}catch(e){return null;} };
  function onOpen(idx){ return { onEnter:function(a){ try{this.path=a[idx].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(r){ var fd=r.toInt32(); if(fd>=0&&this.path&&STORE_RE.test(this.path)) fdmap[fd]=this.path; } }; }
  var openat=E('openat'), openp=E('open');
  if(openat) Interceptor.attach(openat,onOpen(1));
  if(openp)  Interceptor.attach(openp,onOpen(0));
  var writep=E('write'), pwritep=E('pwrite')||E('pwrite64');
  if(writep) Interceptor.attach(writep,{ onEnter:function(a){ this.fd=a[0].toInt32(); this.buf=a[1]; this.n=a[2].toInt32(); },
    onLeave:function(r){ var ret=r.toInt32(); if(ret>0){ var m=ret>4096?4096:ret; grabWrite('write',this.fd,rd(this.buf,m),ret); } }});
  if(pwritep) Interceptor.attach(pwritep,{ onEnter:function(a){ this.fd=a[0].toInt32(); this.buf=a[1]; },
    onLeave:function(r){ var ret=r.toInt32(); if(ret>0){ var m=ret>4096?4096:ret; grabWrite('pwrite',this.fd,rd(this.buf,m),ret); } }});
  // writev/pwritev: a[1]=iovec*, a[2]=iovcnt
  function onWritev(name){ return { onEnter:function(a){ this.fd=a[0].toInt32(); this.iov=a[1]; this.cnt=a[2].toInt32(); },
    onLeave:function(r){ var ret=r.toInt32(); if(ret<=0) return; if(!fdmap[this.fd]) return;
      var out=''; var got=0; for(var i=0;i<this.cnt&&got<4096;i++){ try{
        var base=this.iov.add(i*16).readPointer(); var len=this.iov.add(i*16+8).readU64().toNumber();
        var m=Math.min(len,4096-got); var h=rd(base,m); if(h){ out+=h; got+=m; } }catch(e){break;} }
      if(out) grabWrite(name,this.fd,out,ret); }}; }
  var writev=E('writev'), pwritev=E('pwritev')||E('pwritev64');
  if(writev) Interceptor.attach(writev,onWritev('writev'));
  if(pwritev) Interceptor.attach(pwritev,onWritev('pwritev'));
  // msync: catch mmap-backed store flush; a[0]=addr a[1]=len
  var msyncp=E('msync');
  if(msyncp) Interceptor.attach(msyncp,{ onEnter:function(a){ this.addr=a[0]; this.len=a[1].toInt32(); },
    onLeave:function(){ var m=this.len>4096?4096:this.len; var h=rd(this.addr,m); if(h) send({tag:'MSYNC', len:this.len, head:h.slice(0,128)}); }});
  // rename/renameat: temp->final atomic write
  var renamep=E('rename'), renameatp=E('renameat');
  if(renamep) Interceptor.attach(renamep,{ onEnter:function(a){ var o=null,n=null; try{o=a[0].readUtf8String();}catch(e){} try{n=a[1].readUtf8String();}catch(e){}
    if((o&&STORE_RE.test(o))||(n&&STORE_RE.test(n))) send({tag:'RENAME', old:o, nw:n}); }});
  if(renameatp) Interceptor.attach(renameatp,{ onEnter:function(a){ var o=null,n=null; try{o=a[1].readUtf8String();}catch(e){} try{n=a[3].readUtf8String();}catch(e){}
    if((o&&STORE_RE.test(o))||(n&&STORE_RE.test(n))) send({tag:'RENAME', old:o, nw:n}); }});
  send({tag:'IOHOOK'});
}

function install(base){
  if(installed) return; installed=true; var A=function(o){return base.add(o);};
  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){ var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    var k=rd(a[1],kb); if(k){ var id=kb+':'+k; if(!keys[id]){keys[id]=1; send({tag:'KEY',kb:kb,key:k});} lastKey[Process.getCurrentThreadId()]={key:k,kb:kb}; } }});
  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){ var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    var key=rd(a[1],kb), iv=rd(a[3],16); var tid=Process.getCurrentThreadId();
    if(key) lastKey[tid]={key:key,kb:kb}; if(iv) lastIV[tid]=iv;
    var id=kb+':'+(key||'')+':'+(iv||''); if(!einits[id]){einits[id]=1; send({tag:'EINIT',kb:kb,key:key,iv:iv});} }});
  Interceptor.attach(A(OFF.RDR),{ onEnter:function(a){ this.pbuf=a[1]; this.plen=a[2]; try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
    onLeave:function(){ if(!this.path||!STORE_RE.test(this.path)) return; var len=0,buf=null;
      try{len=this.plen.readU64().toNumber();}catch(e){try{len=this.plen.readU32();}catch(e2){}} try{buf=this.pbuf.readPointer();}catch(e){}
      var head=(buf&&len)?rd(buf,Math.min(len,128)):null; send({tag:'RDR', path:this.path, len:len, head:head}); }});
  // encrypt prims in-window after a store write-open (plaintext IN -> ciphertext OUT)
  function hookEnc(off,name){ Interceptor.attach(A(off),{ onEnter:function(a){ this.win=(Date.now()<=armUntil||Object.keys(fdmap).length>0);
      this.tid=Process.getCurrentThreadId(); this.in=a[1]; this.out=a[2]; this.len=(function(){try{return a[3].toInt32();}catch(e){return 16;}})(); },
    onLeave:function(){ if(!this.win) return; var n=(this.len>0&&this.len<=256)?this.len:16; var ih=rd(this.in,n), oh=rd(this.out,n);
      if(!ih&&!oh) return; var lk=lastKey[this.tid]||{}, iv=lastIV[this.tid]||null;
      var id=name+'|'+(ih?ih.slice(0,32):'')+'|'+(lk.key||''); if(fseen[id]) return; fseen[id]=1;
      log.push({prim:name,key:lk.key||null,kb:lk.kb||null,iv:iv,inhex:ih,outhex:oh,len:this.len}); }}); }
  hookEnc(OFF.BENC,'BENC'); hookEnc(OFF.CBCE,'CBCE');
  send({tag:'READY', base:base.toString(), preloaded:preloaded});
}

(function(){
  try{ hookIO(); }catch(e){ send({tag:'IOHOOK_ERR',e:String(e)}); }
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
  status:function(){ return {installed:installed, nwrite:wlog.length, nfd:Object.keys(fdmap).length,
    nkey:Object.keys(keys).length, neinit:Object.keys(einits).length, nenc:log.length}; },
  dump:function(){ return {writes:wlog, keys:keys, einits:einits, enc:log, fdmap:fdmap}; }
};

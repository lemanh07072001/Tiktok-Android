'use strict';
// STORE ORACLE v7 — write-side capture with crypto look-back ring.
// Warm session => stores are WRITTEN (not read). At write, plaintext already
// encrypted -> ciphertext in hand. A bounded ring of recent metasec crypto ops
// lets us byte-match the written ciphertext to a block-crypto out/in => proves
// mode + yields blocks. No match => store uses custom XOR (decisive negative).
// ATTACH-ONLY. No re-register.

var MET = Process.getModuleByName('libmetasec_ov.so');
var LIBC = Process.getModuleByName('libc.so');
var mbase = MET.base;
function M(off){ return mbase.add(off); }
function L(n){ return LIBC.getExportByName(n); }

var OFF = { DISP:0x10dc18, BENC:0x159d1c, BDEC:0x15997c, CBCE:0x159de4, CBCD:0x159f58, EINIT:0x159d60 };

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;} return s; }
function rd(p,n){ try{return p.readByteArray(n);}catch(e){return null;} }

var STORE_DIR = 'mssdk/ov';
var fdMap = {};      // fd -> path
var fileMap = {};    // FILE* -> path
var ring = [];       // recent crypto events {ts,name,in,out}
var RING_MAX = 600;
var lastEinit = null;
var writeBufs = {};  // store -> latest full hex (for offline DIFF)
var events = [];

function pushRing(name, inp, outp){
  var IN = rd(inp,16), OUT = rd(outp,16);
  ring.push({ts:Date.now(), name:name, in:b2h(IN), out:b2h(OUT)});
  if(ring.length > RING_MAX) ring.shift();
}

// ---- metasec crypto: always-on ring ----
function hookBlk(off,name){
  Interceptor.attach(M(off), { onEnter:function(a){ this.i=a[1]; this.o=a[2]; },
    onLeave:function(){ try{ pushRing(name,this.i,this.o); }catch(e){} } });
}
hookBlk(OFF.BENC,'BENC'); hookBlk(OFF.BDEC,'BDEC'); hookBlk(OFF.CBCE,'CBCE'); hookBlk(OFF.CBCD,'CBCD');
Interceptor.attach(M(OFF.DISP), { onEnter:function(a){
  var mode=-1; try{mode=a[0].readPointer().readU32();}catch(e){}
  ring.push({ts:Date.now(), name:'DISP', mode:mode});
  if(ring.length>RING_MAX) ring.shift();
}});
Interceptor.attach(M(OFF.EINIT), { onEnter:function(a){
  var kb=-1; try{kb=a[2].toInt32();}catch(e){}
  var uk=null,iv=null;
  try{uk=b2h(rd(a[1], kb>0&&kb<=32?kb:16));}catch(e){}
  try{iv=b2h(rd(a[3],16));}catch(e){}
  lastEinit={ts:Date.now(),kb:kb,key:uk,iv:iv};
}});

function isStore(path){ return path && (path.indexOf(STORE_DIR)>=0 || /\.ms[a-z0-9]*[_.]/.test(path.split('/').pop())); }

function onStoreWrite(path, buf, n){
  var base = path.split('/').pop();
  var cap = Math.min(n, 4096);
  var full = b2h(rd(buf, cap));
  if(!full) return;
  writeBufs[base] = full;
  var now = Date.now();
  // byte-match ciphertext against recent ring block-crypto out/in
  var matches = [];
  for(var i=ring.length-1;i>=0 && (now-ring[i].ts)<=400;i--){
    var e=ring[i];
    if(e.out && full.indexOf(e.out)>=0) matches.push({name:e.name,how:'out',blk:e.out,dt:now-e.ts});
    if(e.in && full.indexOf(e.in)>=0)  matches.push({name:e.name,how:'in', blk:e.in, dt:now-e.ts});
  }
  var ein = (lastEinit && (now-lastEinit.ts)<=500) ? lastEinit : null;
  var ev = {t:'WRITE', store:base, n:n, head:full.slice(0,32), tail:full.slice(-32),
            matches:matches.slice(0,8), einit:ein};
  events.push(ev);
  send({tag:'WRITE', store:base, n:n, head:ev.head, matched:matches.length,
        matchNames:matches.map(function(m){return m.name+':'+m.how+':'+m.dt+'ms';}).slice(0,6),
        einit: ein?{kb:ein.kb,key:ein.key,iv:ein.iv,dt:now-ein.ts}:null});
}

// ---- libc I/O ----
Interceptor.attach(L('openat'), {
  onEnter:function(a){ try{this.path=a[1].readUtf8String();}catch(e){this.path=null;} },
  onLeave:function(r){ if(this.path&&isStore(this.path)){ var fd=r.toInt32(); if(fd>=0){fdMap[fd]=this.path; send({tag:'OPEN',fn:'openat',fd:fd,path:this.path.split('/').pop()});}} }
});
Interceptor.attach(L('open'), {
  onEnter:function(a){ try{this.path=a[0].readUtf8String();}catch(e){this.path=null;} },
  onLeave:function(r){ if(this.path&&isStore(this.path)){ var fd=r.toInt32(); if(fd>=0){fdMap[fd]=this.path; send({tag:'OPEN',fn:'open',fd:fd,path:this.path.split('/').pop()});}} }
});
Interceptor.attach(L('fopen'), {
  onEnter:function(a){ try{this.path=a[0].readUtf8String();this.mode=a[1].readUtf8String();}catch(e){this.path=null;} },
  onLeave:function(r){ if(this.path&&isStore(this.path)&&!r.isNull()){ fileMap[r.toString()]=this.path; send({tag:'FOPEN',mode:this.mode,path:this.path.split('/').pop()});} }
});
Interceptor.attach(L('write'), {
  onEnter:function(a){ var fd=a[0].toInt32(); if(fdMap[fd]){ this.p=fdMap[fd]; this.buf=a[1]; this.n=a[2].toInt32(); } },
  onLeave:function(){ if(this.p){ try{ onStoreWrite(this.p,this.buf,this.n);}catch(e){ send({tag:'ERRW',e:e.message}); } } }
});
Interceptor.attach(L('fwrite'), {
  onEnter:function(a){ var fp=a[3].toString(); if(fileMap[fp]){ this.p=fileMap[fp]; this.buf=a[0]; this.n=a[1].toInt32()*a[2].toInt32(); } },
  onLeave:function(){ if(this.p){ try{ onStoreWrite(this.p,this.buf,this.n);}catch(e){} } }
});
Interceptor.attach(L('rename'), {
  onEnter:function(a){ try{var o=a[0].readUtf8String(),nw=a[1].readUtf8String(); if(isStore(o)||isStore(nw)) send({tag:'RENAME',from:o.split('/').pop(),to:nw.split('/').pop()});}catch(e){} }
});
Interceptor.attach(L('close'), {
  onEnter:function(a){ var fd=a[0].toInt32(); if(fdMap[fd]) delete fdMap[fd]; }
});

rpc.exports = { dump:function(){return {events:events, writeBufs:writeBufs};}, ring:function(){return ring.slice(-40);} };
send({tag:'READY7', mbase:mbase.toString()});

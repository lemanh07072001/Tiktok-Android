'use strict';
// STORE ORACLE v7 — RDR-armed, firehose-proof, frida-17 loader, NO nudge.
// Fix vs v6: (1) Process.getModuleByName is NOT a function in frida 17 ->
//   enumerate + android_dlopen fallback (libmetasec loads LATE ~t33).
//   (2) all hooks wrapped in install(base), called once module present.
//   (3) light: crypto hooks are cheap no-ops outside the RDR-armed window,
//   so the splash activity does NOT ANR (the t27 kill was our overhead+nudge).
//
// Strategy: RDR(0xe2df0) reads a store .ms* file -> learn exact path + ciphertext,
//   and ARM a 120ms window. Only AES primitives that fire INSIDE that window are
//   logged -> isolates the store's inline decrypt from the request-sign firehose.
//   crypto in-window  -> mode + in/out blocks (keystream/plaintext) captured.
//   NOTHING in-window  -> decisive proof store uses a custom PRG, not the AES module.
// ATTACH-ONLY. No re-register.

var MOD = 'libmetasec_ov.so';

var OFF = {
  RDR : 0xe2df0,   // file reader:  RDR(x0=path, x1=&buf, x2=&len)
  DISP: 0x10dc18,  // crypt_dispatch: *(*x0)=mode
  BENC: 0x159d1c,  // AES block encrypt core
  BDEC: 0x15997c,  // AES block decrypt core
  CBCE: 0x159de4,  // CBC encrypt
  CBCD: 0x159f58,  // CBC decrypt
  STRM: 0x15a598,  // mode3 stream driver (length-preserving)
  EINIT:0x159d60,  // key init (x0=ctx,x1=userKey,x2=keyBYTES,x3=IV)
  KSCH: 0x1591bc,  // key schedule (x1=userKey, x2=keyBYTES)
};

// store filename patterns: .mss_ .msp_ .msf3_ .msfs .msf ...
var STORE_RE = /\.ms(s|p|f3|fs|f)?[_.]/;

var armUntil = 0;
var curStore = null;
var log = [];
var seen = {};
var WINDOW_MS = 120;

function b2h(ab){
  if(!ab) return null;
  var u = new Uint8Array(ab), s='';
  for(var i=0;i<u.length;i++){ var h=u[i].toString(16); s += (h.length<2?'0':'')+h; }
  return s;
}
function readN(p, n){ try { return p.readByteArray(n); } catch(e){ return null; } }

function install(base){
  function A(off){ return base.add(off); }

  // ---- RDR: identify store + capture ciphertext, arm window ----
  Interceptor.attach(A(OFF.RDR), {
    onEnter: function(a){ this.pbuf=a[1]; this.plen=a[2];
      try { this.path = a[0].readUtf8String(); } catch(e){ this.path=null; } },
    onLeave: function(){
      if(!this.path) return;
      var name = this.path.split('/').pop();
      if(!STORE_RE.test(name)) return;
      var len=0, buf=null;
      try { len = this.plen.readU64().toNumber(); } catch(e){ try{ len=this.plen.readU32(); }catch(e2){} }
      try { buf = this.pbuf.readPointer(); } catch(e){}
      var head = (buf && len) ? readN(buf, Math.min(len,48)) : null;
      curStore = name; armUntil = Date.now() + WINDOW_MS;
      log.push({t:'RDR', store:name, len:len, head:head?b2h(head):null});
      send({tag:'RDR', store:name, len:len, head:head?b2h(head):null});
    }
  });

  // ---- crypt_dispatch: mode, in-window only ----
  Interceptor.attach(A(OFF.DISP), {
    onEnter: function(a){
      if(Date.now() > armUntil) return;
      var mode=-1; try { mode = a[0].readPointer().readU32(); } catch(e){}
      log.push({t:'DISP', store:curStore, mode:mode}); send({tag:'DISP', store:curStore, mode:mode});
    }
  });

  // ---- block/CBC/stream primitives: capture in/out, in-window only ----
  function hookBlk(off, name){
    Interceptor.attach(A(off), {
      onEnter: function(a){ this.win = (Date.now() <= armUntil);
        if(!this.win) return; this.a1=a[1]; this.a2=a[2]; this.store=curStore; },
      onLeave: function(){ if(!this.win) return;
        var IN=readN(this.a1,16), OUT=readN(this.a2,16);
        var k=name+'|'+this.store+'|'+b2h(IN); if(seen[k]) return; seen[k]=1;
        log.push({t:name, store:this.store, in16:b2h(IN), out16:b2h(OUT)});
        send({tag:name, store:this.store, in16:b2h(IN), out16:b2h(OUT)});
      }
    });
  }
  hookBlk(OFF.BENC,'BENC'); hookBlk(OFF.BDEC,'BDEC');
  hookBlk(OFF.CBCE,'CBCE'); hookBlk(OFF.CBCD,'CBCD');
  hookBlk(OFF.STRM,'STRM');

  // ---- key init: always log (rare) -> key+IV; flag if store-window ----
  Interceptor.attach(A(OFF.EINIT), {
    onEnter: function(a){
      var inWin = (Date.now() <= armUntil);
      var kb=-1; try { kb = a[2].toInt32(); } catch(e){}
      var uk=null, iv=null;
      try { uk = b2h(readN(a[1], kb>0&&kb<=32?kb:16)); } catch(e){}
      try { iv = b2h(readN(a[3], 16)); } catch(e){}
      log.push({t:'EINIT', win:inWin, store:inWin?curStore:null, kb:kb, key:uk, iv:iv});
      send({tag:'EINIT', win:inWin, store:inWin?curStore:null, kb:kb, key:uk, iv:iv});
    }
  });

  // ---- key schedule: catch keys even if EINIT is inlined elsewhere ----
  Interceptor.attach(A(OFF.KSCH), {
    onEnter: function(a){
      var inWin = (Date.now() <= armUntil);
      var kb=-1; try { kb = a[2].toInt32(); } catch(e){}
      var uk=null; try { uk = b2h(readN(a[1], kb>0&&kb<=32?kb:16)); } catch(e){}
      var k='KSCH|'+uk+'|'+kb; if(seen[k]) return; seen[k]=1;
      log.push({t:'KSCH', win:inWin, store:inWin?curStore:null, kb:kb, key:uk});
      send({tag:'KSCH', win:inWin, store:inWin?curStore:null, kb:kb, key:uk});
    }
  });

  send({tag:'READY', base: base.toString()});
}

// ---- module loader (frida 17): preloaded, else android_dlopen fallback ----
var done = false;
function tryPreloaded(){
  var b = null;
  Process.enumerateModules().forEach(function(m){ if(m.name === MOD) b = m.base; });
  if(b){ done = true; install(b); return true; }
  return false;
}
if(!tryPreloaded()){
  send({tag:'WAIT_DLOPEN'});
  var names = ['android_dlopen_ext','__loader_android_dlopen_ext','dlopen','__loader_dlopen'];
  names.forEach(function(fn){
    var p = Module.findGlobalExportByName ? Module.findGlobalExportByName(fn) : null;
    if(!p) return;
    Interceptor.attach(p, {
      onEnter: function(a){ try { this.path = a[0].readUtf8String(); } catch(e){ this.path=null; } },
      onLeave: function(){
        if(done) return;
        if(this.path && this.path.indexOf(MOD) >= 0){
          var b=null; Process.enumerateModules().forEach(function(m){ if(m.name===MOD) b=m.base; });
          if(b){ done=true; install(b); }
        }
      }
    });
  });
}

rpc.exports = {
  status: function(){ return {done:done, events:log.length}; },
  dump: function(){ return log; },
  clear: function(){ log=[]; seen={}; return true; }
};

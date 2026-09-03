'use strict';
// STORE-LOAD ORACLE — attach at splash (pre-libmetasec), ARM dlopen, catch the
// store decrypt at libmetasec LOAD time. Streams self-verifying tuples so the
// per-session re-key never matters:
//   KEY   : {kb,key}                 (KSCH 0x1591bc: userKey@x1, keyBYTES@x2)
//   EINIT : {kb,key,iv}              (0x159d60: key@x1,kb@x2,IV@x3) -- combined
//   CT    : {prim,key,kb,iv,inhex,outhex,len}  (CBC/block decrypt in/out buffers)
// Offline: AES-dec(key,iv,inhex)==outhex proves the primitive; then match inhex
// against a freshly-pulled disk store blob (same session). NO re-register.
var MOD='libmetasec_ov.so';
var OFF={ KSCH:0x1591bc, EINIT:0x159d60,
          BDEC:0x15997c, BDEC2:0x159618, CBCD:0x159f58, CBCE:0x159de4,
          BENC:0x159d1c };
var installed=false, preloaded=false;
var keys={}, einits={}, cts={}, log=[];
var lastKey={}, lastIV={};

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s='';
  for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function looksPtr(p){ try{ return !p.isNull() && p.compare(ptr('0x10000'))>0 && p.compare(ptr('0x8000000000'))<0; }catch(e){return false;} }
function rd(p,n){ try{ if(!looksPtr(p)) return null; return b2h(p.readByteArray(n)); }catch(e){return null;} }
function kbnorm(v){ return (v===16||v===24||v===32)?v:16; }

function recKey(tid,keyhex,kb){
  if(!keyhex) return;
  var k=kb+':'+keyhex;
  if(!keys[k]){ keys[k]=1; send({tag:'KEY',kb:kb,key:keyhex}); } else keys[k]++;
  lastKey[tid]={key:keyhex,kb:kb};
}
function recEinit(tid,keyhex,kb,ivhex){
  if(keyhex) lastKey[tid]={key:keyhex,kb:kb};
  if(ivhex)  lastIV[tid]=ivhex;
  var id=kb+':'+(keyhex||'')+':'+(ivhex||'');
  if(!einits[id]){ einits[id]=1; send({tag:'EINIT',kb:kb,key:keyhex,iv:ivhex}); } else einits[id]++;
}
function recCT(tid,prim,inhex,outhex,len){
  var lk=lastKey[tid]||{}, iv=lastIV[tid]||null;
  var id=prim+'|'+(inhex?inhex.slice(0,32):'')+'|'+(lk.key||'');
  if(cts[id]) { cts[id]++; return; } cts[id]=1;
  var ev={prim:prim,key:lk.key||null,kb:lk.kb||null,iv:iv,inhex:inhex,outhex:outhex,len:len};
  log.push(ev); send({tag:'CT',ev:ev});
}

function install(base){
  if(installed) return; installed=true;
  var A=function(o){ return base.add(o); };

  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    recKey(Process.getCurrentThreadId(), rd(a[1],kb), kb);
  }});

  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    recEinit(Process.getCurrentThreadId(), rd(a[1],kb), kb, rd(a[3],16));
  }});

  // CBC decrypt: (ctx x0, in x1, out x2, len x3, ivptr x4?) — capture up to 64B in/out
  function hookCBC(off,name){
    Interceptor.attach(A(off),{
      onEnter:function(a){ this.tid=Process.getCurrentThreadId(); this.in=a[1]; this.out=a[2];
        this.len=(function(){try{return a[3].toInt32();}catch(e){return -1;}})(); },
      onLeave:function(){ var n=(this.len>0&&this.len<=64)?this.len:64;
        var ih=rd(this.in,n), oh=rd(this.out,n);
        if(ih||oh) recCT(this.tid,name,ih,oh,this.len); }
    });
  }
  hookCBC(OFF.CBCD,'CBCD'); hookCBC(OFF.CBCE,'CBCE');
  // block cores: single 16B block in=a1 out=a2
  function hookBLK(off,name){
    Interceptor.attach(A(off),{
      onEnter:function(a){ this.tid=Process.getCurrentThreadId(); this.in=a[1]; this.out=a[2]; },
      onLeave:function(){ var ih=rd(this.in,16), oh=rd(this.out,16);
        if(ih||oh) recCT(this.tid,name,ih,oh,16); }
    });
  }
  hookBLK(OFF.BDEC,'BDEC'); hookBLK(OFF.BDEC2,'BDEC2'); hookBLK(OFF.BENC,'BENC');

  send({tag:'READY', base:base.toString(), preloaded:preloaded});
}

(function(){
  var m=null;
  Process.enumerateModules().forEach(function(x){ if(x.name===MOD) m=x; });
  if(m){ preloaded=true; install(m.base); return; }
  ['android_dlopen_ext','dlopen','__loader_dlopen'].forEach(function(fn){
    var p=Module.findGlobalExportByName?Module.findGlobalExportByName(fn):null;
    if(!p){ try{p=Module.getGlobalExportByName(fn);}catch(e){} }
    if(p){ Interceptor.attach(p,{ onLeave:function(){
      if(installed) return;
      Process.enumerateModules().forEach(function(x){ if(x.name===MOD) install(x.base); });
    }}); }
  });
  send({tag:'WAIT_DLOPEN'});
})();

rpc.exports={
  status:function(){ return {installed:installed, preloaded:preloaded,
    nkeys:Object.keys(keys).length, neinit:Object.keys(einits).length, ncts:Object.keys(cts).length}; },
  dump:function(){ return {keys:keys, einits:einits, cts:log}; }
};

'use strict';
// EVP CONTENT-MATCH ORACLE — Track C, attach-only, NO re-register.
// Idea: the store key MUST flow through KSCH(0x1591bc)/EINIT(0x159d60) at least once
// during a store-touching session (static lift proved: no hardcoded key, no alt schedule).
// So we (1) COLLECT every distinct (key,keyBytes,IV) that passes through KSCH/EINIT, and
// (2) CONTENT-MATCH: when any cipher op's in/out buffer head equals a known ground-truth
// store-blob prefix, we PIN the paired key (per-thread lastKey). Offline we brute the small
// distinct-key set against the 12 GT blobs. The temporal window is irrelevant.
var MOD='libmetasec_ov.so';
var OFF={
  DISP1:0x10d064, DISP2:0x10db6c,   // EVP cipher dispatch (all modes see full buffer)
  KSCH :0x1591bc,                   // AES key schedule (ctx=x0, userKey=x1, keyBYTES=x2)
  EINIT:0x159d60,                   // key init (ctx,x1=userKey,x2=keyBYTES,x3=IV)
  BENC :0x159d1c, BDEC:0x15997c,    // block enc/dec cores
  BDEC2:0x159618,                   // block-decrypt core (do-cipher)
  CBCE :0x159de4, CBCD:0x159f58     // CBC enc/dec (full buffers + IV)
};
var HEADS=new Set([
  '06c89feae2d013cc',
  '1035d1b5c49a1700',
  '3963d82f859fa8574fade519b3eeff20',
  '3963d82f859fa8574fade519b3eeff2007ae2a9a75d61814e27b20fa21d22e63',
  '40a68652772bfcab2e18a6ebfa7ff323',
  '593729d3393d665d',
  '5b1c7deb16133991',
  '7bae62270249288934940a1a22ad0263',
  '7bae62270249288934940a1a22ad02631d08e6b16800fa56ccfb73ff84128cc7',
  '84b37a642260df40cee7946927841a52',
  '84b37a642260df40cee7946927841a529debb04fbb0082f2becc7ae412d9b66c',
  '94199bca6d60ed2e',
  'aaefae788585292b0ab00f25e8e45d86',
  'aaefae788585292b0ab00f25e8e45d86b762f60290e55083052833ba1fd30292',
  'df27fcb6e4d2cd4b212e5a68e2ebb824',
  'f9e2d6ccf772dfa51a3ef861a90b6d91',
  'f9e2d6ccf772dfa51a3ef861a90b6d916f3dfd39b51d702a0c09494c4ed0c845'
]);
var TAILS=new Set([
  '06c89feae2d013cc',
  '1035d1b5c49a1700',
  '15f10a0a232e090e9aa0fde6007cd1af54fddb8a79099a87e4dd5acdfb203957',
  '20ca55084ea38ec2bb81d1d749ccacfd',
  '40a68652772bfcab2e18a6ebfa7ff323',
  '54fddb8a79099a87e4dd5acdfb203957',
  '593729d3393d665d',
  '5b1c7deb16133991',
  '674f625200774b5864f8f0f9498dd2ca6843dbefadf18716cec5b022bf3a0fbb',
  '6843dbefadf18716cec5b022bf3a0fbb',
  '94199bca6d60ed2e',
  'aaefae788585292b0ab00f25e8e45d86b762f60290e55083052833ba1fd30292',
  'ae01120686a6d82770a76e24f0ac3976',
  'b762f60290e55083052833ba1fd30292',
  'bf024f10f93f22f40cf0d42fe0b279b920ca55084ea38ec2bb81d1d749ccacfd',
  'df27fcb6e4d2cd4b212e5a68e2ebb824',
  'f0032d0e590405461132da808f5abd11ae01120686a6d82770a76e24f0ac3976'
]);

var lastKey={};   // tid -> {key,kb}
var lastIV={};    // tid -> ivhex
var keys={};      // distinct "kb:keyhex" -> count   (the FULL collection = fallback brute set)
var ivs={};       // distinct ivhex -> count
var hits=[];      // content-match events (PINNED store key)
var log=[];
var installed=false;

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s='';
  for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function looksPtr(p){ try{ var v=p.toString(); // reject small ints / len args
    return !p.isNull() && p.compare(ptr('0x10000'))>0 && p.compare(ptr('0x8000000000'))<0; }catch(e){return false;} }
function head(p,n){ try{ if(!looksPtr(p)) return null; return b2h(p.readByteArray(n)); }catch(e){return null;} }
function isStore(h){ if(!h) return false;
  var h16=h.slice(0,32), h32=h; return HEADS.has(h16)||HEADS.has(h32)||TAILS.has(h16); }

function recKey(tid,keyhex,kb,ivhex){
  if(keyhex){ var k=kb+':'+keyhex; if(!keys[k]){ keys[k]=1; send({tag:'KEY',kb:kb,key:keyhex}); } else keys[k]++; lastKey[tid]={key:keyhex,kb:kb}; }
  if(ivhex){ if(!ivs[ivhex]){ ivs[ivhex]=1; send({tag:'IV',iv:ivhex}); } else ivs[ivhex]++; lastIV[tid]=ivhex; }
}
function pinHit(name,dir,idx,h,tid){
  var lk=lastKey[tid]||{}, iv=lastIV[tid]||null;
  var ev={t:name,dir:dir,arg:idx,head:h,key:lk.key||null,kb:lk.kb||null,iv:iv,tid:tid};
  hits.push(ev); send({tag:'HIT',ev:ev});
}

function install(base){
  if(installed) return; installed=true;
  var A=function(o){ return base.add(o); };

  Interceptor.attach(A(OFF.KSCH),{ onEnter:function(a){
    var kb=-1; try{kb=a[2].toInt32();}catch(e){}
    if(kb!==16&&kb!==24&&kb!==32) kb=16;
    var key=null; try{key=b2h(a[1].readByteArray(kb));}catch(e){}
    recKey(Process.getCurrentThreadId(),key,kb,null);
  }});

  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){
    var kb=-1; try{kb=a[2].toInt32();}catch(e){}
    if(kb!==16&&kb!==24&&kb!==32) kb=16;
    var key=null,iv=null;
    try{key=b2h(a[1].readByteArray(kb));}catch(e){}
    try{iv=b2h(a[3].readByteArray(16));}catch(e){}
    recKey(Process.getCurrentThreadId(),key,kb,iv);
  }});

  function hookCipher(off,name){
    Interceptor.attach(A(off),{
      onEnter:function(a){
        this.name=name; this.tid=Process.getCurrentThreadId();
        this.a=[a[0],a[1],a[2],a[3]];
        for(var i=0;i<4;i++){ var h=head(a[i],32);
          if(isStore(h)){ pinHit(name,'in',i,h,this.tid); break; } }
      },
      onLeave:function(){
        for(var i=0;i<4;i++){ var h=head(this.a[i],32);
          if(isStore(h)){ pinHit(name,'out',i,h,this.tid); } }
      }
    });
  }
  hookCipher(OFF.DISP1,'DISP1'); hookCipher(OFF.DISP2,'DISP2');
  hookCipher(OFF.CBCD,'CBCD');   hookCipher(OFF.CBCE,'CBCE');
  hookCipher(OFF.BDEC,'BDEC');   hookCipher(OFF.BENC,'BENC');
  hookCipher(OFF.BDEC2,'BDEC2');
  send({tag:'READY', base:base.toString()});
}

// resolve base now (attach to settled app: module already loaded); fallback dlopen
(function(){
  var m=null;
  Process.enumerateModules().forEach(function(x){ if(x.name===MOD) m=x; });
  if(m){ install(m.base); return; }
  ['android_dlopen_ext','dlopen'].forEach(function(fn){
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
  status:function(){ return {installed:installed, nkeys:Object.keys(keys).length,
                             nivs:Object.keys(ivs).length, nhits:hits.length}; },
  dump:function(){ return {keys:keys, ivs:ivs, hits:hits}; }
};

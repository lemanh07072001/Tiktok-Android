'use strict';
// ===== AES store-key ORACLE v5 =====
// Capture store key DIRECTLY from the reused cipher context at CBC time.
// Rationale: store cipher ctx is built ONCE at startup (KEYSCHED before attach),
// then reused. ctx+0x00 holds round-key-0 = wswap4(userKey). Recover userKey
// by byte-reversing each 4-byte word. IV lives at ctx+0x1e8.
var LIB='libmetasec_ov.so';
var OFF={KEYSCHED:0x1591bc, ENC_INIT:0x159d60, CBC_DEC:0x159f58, BLK_DEC:0x15997c, CBC_ENC:0x159de4};
var IVOFF=0x1e8;
// FRESH on-disk heads (post 20:44 write) -> tag store operations
var HEADS={
 'c3b27a642260175cb483156827c01af2':'msp_092f(130)',
 '1763d82f859fa8574fade519b3eeff20':'msp_589c(345)',
 '75aa62270249304c2290151a22d4ca79':'mss_9b8e(262)',
 'aa87b8828adc698fe6354c2c9180df52':'msf3_5a78(16)',
 'aaefae788585292b0ab00f25e8e45d86':'msf3_5bbd(32)'
};
function hx(p,n){ try{ return p.readByteArray(n); }catch(e){ return null; } }
function tohex(ab){ if(!ab) return '<null>'; var u=new Uint8Array(ab),s=''; for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+= h.length<2?'0'+h:h;} return s; }
function H(p,n){ return tohex(hx(p,n)); }
// wswap4: byte-reverse each 32-bit word of a 16-byte hex string -> undo KEYSCHED rev
function wswap4(hex){ if(!hex||hex.length<32) return hex; var o=''; for(var w=0;w<4;w++){var b=w*8; o+=hex.substr(b+6,2)+hex.substr(b+4,2)+hex.substr(b+2,2)+hex.substr(b+0,2);} return o; }
function ctxKey(ctx){ var rk0=H(ctx,16); return {rk0:rk0, key:wswap4(rk0)}; }
function ctxIV(ctx){ return H(ctx.add(IVOFF),16); }
var NOISE={"8252970d959b06db102e17d85c0ec1af":1,"b114249b7bed9d2691d70c60d69f9c4f":1};
function small(len){ return len>0 && len<=512; }
function tag(k){ return NOISE[k]?"":" <<<<<<<<<< STORE? novel-key"; }
var armed=false, nEnc=0, nDec=0;
function arm(base){
  if(armed) return; armed=true;
  console.log('[ARM] base='+base+' [ORACLE v5]');
  // KEYSCHED (request-sign keys pass here; store already done pre-attach)
  Interceptor.attach(base.add(OFF.KEYSCHED),{ onEnter:function(a){
    var kb=this.context.x2.toInt32(); var klen=(kb>=16&&kb<=32)?kb:16;
    console.log('[KEYSCHED] kb='+kb+' userKey='+H(this.context.x1,16)+(klen>16?(' k2='+H(this.context.x1.add(16),klen-16)):''));
  }});
  Interceptor.attach(base.add(OFF.ENC_INIT),{ onEnter:function(a){
    console.log('[INIT] key='+H(this.context.x1,16)+' iv='+H(this.context.x3,16)+' kb='+this.context.x2.toInt32());
  }});
  // CBC_ENC: x0=ctx x1=pt_in x2=ct_out w3=len  -> STORE WRITE path
  Interceptor.attach(base.add(OFF.CBC_ENC),{ onEnter:function(a){
    var len=this.context.x3.toInt32(); if(!small(len)) return;
    this._ctx=this.context.x0; this._in=this.context.x1; this._out=this.context.x2; this._len=len;
    var k=ctxKey(this._ctx); nEnc++;
    console.log('[ENC#'+nEnc+'] len='+len+' KEY='+k.key+' IV='+ctxIV(this._ctx)+tag(k.key));
    console.log('[ENC#'+nEnc+' PT] '+H(this._in,Math.min(len,64)));
  }, onLeave:function(r){ if(this._out&&this._len){ console.log('[ENC#'+nEnc+' CT] '+H(this._out,Math.min(this._len,64))); } }});
  // CBC_DEC: x0=ctx x1=ct_in x2=pt_out w3=len  -> STORE READ path (cache-miss only)
  Interceptor.attach(base.add(OFF.CBC_DEC),{ onEnter:function(a){
    var len=this.context.x3.toInt32(); if(!small(len)) return;
    this._ctx=this.context.x0; this._in=this.context.x1; this._out=this.context.x2; this._len=len;
    var h=H(this._in,16); var flag=HEADS[h]?(' <<<< ONDISK '+HEADS[h]):''; var k=ctxKey(this._ctx); nDec++;
    console.log('[DEC#'+nDec+'] len='+len+' KEY='+k.key+' IV='+ctxIV(this._ctx)+' ct_head='+h+flag+tag(k.key));
  }, onLeave:function(r){ if(this._out&&this._len&&this._len<=256){ console.log('[DEC#'+nDec+' PT] '+H(this._out,this._len)); } }});
  console.log('[ARMED] enc+dec ctx-key capture live, size<=512');
}
function tryArm(){ var m=Process.findModuleByName(LIB); if(m){ arm(m.base); return true;} return false; }
if(!tryArm()){
  ['android_dlopen_ext','dlopen'].forEach(function(sym){
    var f=null; try{ f=Module.findGlobalExportByName?Module.findGlobalExportByName(sym):null; }catch(e){}
    if(!f){var ld=Process.findModuleByName('libdl.so'); if(ld) f=ld.findExportByName(sym);} if(!f) return;
    Interceptor.attach(f,{ onLeave:function(r){ tryArm(); }});
  });
  console.log('[WAIT] libmetasec not loaded yet; armed dlopen watchers');
}

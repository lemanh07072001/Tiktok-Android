'use strict';
// _mswire_crypt.js — passive wire-blob crypt capture (get_token task, notes/73 §5).
// Goal: catch the ENCRYPT of mssdk request f4 (704/160/112B) and DECRYPT of
// response f6 (176/64/32B) inside libmetasec_ov.so during NORMAL app usage.
// NO store deletion, NO forced trigger, NO network forcing. Secrets go to the
// python driver via send() -> git-ignored cap.noindex/ ONLY; stdout prints tags.
// Offsets: build 45.5.4 libmetasec_ov.so 2032384B (notes 54/56, phone-verified).
var MOD='libmetasec_ov.so';
var OFF={KEYSCHED:0x1591bc, CBC_ENC:0x159de4, CBC_DEC:0x159f58,
         E192:0x15a1dc, E256STREAM:0x15a598, ENC_INIT:0x159d60,
         RC4:0x10bbd0, RC4_STORE_RET:0x1184a8, SM3:0x9fdac,
         BLK_ENC:0x159d1c, BLK_DEC:0x159618};
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function rN(p,n){try{if(!p||p.isNull())return null;var r=Process.findRangeByAddress(p);if(!r||r.protection[0]!=='r')return null;return p.readByteArray(n);}catch(e){return null;}}
function tt(p,max){ // MSString {cap@0,len@4,data@8} (note-56 §73)
  try{ if(!p||p.isNull())return null;
    var cap=p.readU32(),sz=p.add(4).readU32(),d=p.add(8).readPointer();
    if(sz>0&&sz<65536&&cap>=sz){ var b=rN(d,Math.min(sz,max||4096)); return b?{sz:sz,hx:b2h(b)}:null;}
  }catch(e){} return null;}
// wire-blob + report sizes -> FULL buffer dumps (notes/73 §5)
var FULL={32:1,48:1,64:1,112:1,128:1,160:1,176:1,192:1,544:1,560:1,576:1,592:1,608:1,624:1,640:1,704:1,720:1,736:1};
function wswap4(hex){ if(!hex||hex.length<32) return hex; var o=''; for(var w=0;w<4;w++){var b=w*8; o+=hex.substr(b+6,2)+hex.substr(b+4,2)+hex.substr(b+2,2)+hex.substr(b+0,2);} return o; }
function lr(){try{var l=this.context.lr; var m=Process.findModuleByAddress(l); return m?('%s+%x'.replace('%s',m.name).replace('%x',l.sub(m.base).toInt32())):l.toString();}catch(e){return '?';}}
var n={ks:0,enc:0,dec:0,st:0,rc4:0,drop:0};
var seen={};
function once(k){ if(seen[k]){n.drop++;return false;} seen[k]=1; return true; }
function install(base){
  send({k:'BASE',base:base.toString()});
  // 1) AES keysched: EVERY userKey — wire keys pass here (dedupe identical keys)
  Interceptor.attach(base.add(OFF.KEYSCHED),{onEnter:function(a){
    var kb=0; try{kb=this.context.x2.toInt32();}catch(e){}
    if(kb<16||kb>32) return;
    var key=b2h(rN(this.context.x1,kb));
    n.ks++;
    if(!once('KS'+key+kb)) return;
    send({k:'KS',i:n.ks,kb:kb,key:key,lr:lr.call(this)});
  }});
  // 2) CBC encrypt: x0=ctx x1=pt_in x2=ct_out w3=len
  Interceptor.attach(base.add(OFF.CBC_ENC),{onEnter:function(a){
    var len=0; try{len=this.context.x3.toInt32();}catch(e){}
    if(len<=0||len>4096) return;
    this._i=this.context.x0;this._in=this.context.x1;this._out=this.context.x2;this._l=len;this._hit=true;
    var full=FULL[len]?1:0;
    n.enc++;
    var rk=b2h(rN(this.context.x0,16));
    send({k:'ENC',i:n.enc,len:len,full:full,
          key:wswap4(rk),iv:b2h(rN(this.context.x0.add(0x1e8),16)),lr:lr.call(this),
          pt_head:b2h(rN(this.context.x1,Math.min(len,48)))});
    if(full) send({k:'ENC_PT',i:n.enc,len:len,pt:b2h(rN(this.context.x1,len))});
  },onLeave:function(r){ if(this._hit){ if(FULL[this._l]) send({k:'ENC_CT',i:n.enc,len:this._l,ct:b2h(rN(this._out,this._l))}); else send({k:'ENC_OUT',i:n.enc,ct_head:b2h(rN(this._out,Math.min(this._l,48)))}); } }});
  // 3) CBC decrypt: same ABI
  Interceptor.attach(base.add(OFF.CBC_DEC),{onEnter:function(a){
    var len=0; try{len=this.context.x3.toInt32();}catch(e){}
    if(len<=0||len>4096) return;
    this._i=this.context.x0;this._in=this.context.x1;this._out=this.context.x2;this._l=len;this._hit=true;
    var full=FULL[len]?1:0;
    n.dec++;
    var rk=b2h(rN(this.context.x0,16));
    send({k:'DEC',i:n.dec,len:len,full:full,
          key:wswap4(rk),iv:b2h(rN(this.context.x0.add(0x1e8),16)),lr:lr.call(this),
          ct_head:b2h(rN(this.context.x1,Math.min(len,48)))});
    if(full) send({k:'DEC_CT',i:n.dec,len:len,ct:b2h(rN(this.context.x1,len))});
  },onLeave:function(r){ if(this._hit){ if(FULL[this._l]) send({k:'DEC_PT',i:n.dec,len:this._l,pt:b2h(rN(this._out,this._l))}); else send({k:'DEC_OUT',i:n.dec,pt_head:b2h(rN(this._out,Math.min(this._l,48)))}); } }});
  // 4) stream/mode3 + E192 init variants (x1=key x2=kb x3=iv per _crypto_oracle)
  [OFF.E192,OFF.E256STREAM,OFF.ENC_INIT].forEach(function(o,nm){
    Interceptor.attach(base.add(o),{onEnter:function(a){
      var kb=0; try{kb=this.context.x2.toInt32();}catch(e){}
      var key=b2h(rN(this.context.x1,(kb>=16&&kb<=32)?kb:16));
      var iv=b2h(rN(this.context.x3,16));
      n.st++;
      if(!once('IN'+key+iv+kb)) return;
      send({k:'INIT',w:nm,kb:kb,key:key,iv:iv,lr:lr.call(this)});
    }});});
  // 5) RC4 — ALL callers incl. STORE site (response content lands in store pre-encrypt)
  Interceptor.attach(base.add(OFF.RC4),{onEnter:function(a){
    var isStore=false; try{ isStore=this.returnAddress.equals(base.add(OFF.RC4_STORE_RET)); }catch(e){}
    var in0=tt(this.context.x0,4096), key0=tt(this.context.x1,256);
    if(!in0) return;
    n.rc4++;
    if(isStore){
      if(!once('ST'+in0.sz+(in0.hx||'').substr(0,16))) return;
      send({k:'RC4STORE',i:n.rc4,insz:in0.sz,inhx:in0.hx,key:key0,lr:lr.call(this)});
      this._st=true; this._x0=this.context.x0;
      return;
    }
    send({k:'RC4',i:n.rc4,insz:in0.sz,inhx:(in0.sz<=300)?in0.hx:null,key:key0,lr:lr.call(this)});
  },onLeave:function(r){ if(this._st){ var post=tt(this._x0,4096); if(post) send({k:'RC4STORE_OUT',insz:post.sz,hx:post.hx}); } }});
  // 6) SM3 full-message entry (x0=data, x1=len) — inner chain tracer
  Interceptor.attach(base.add(OFF.SM3),{onEnter:function(a){
    var len=0; try{len=this.context.x1.toInt32();}catch(e){}
    if(len<=0||len>8192) return;
    n.sm3=(n.sm3||0)+1;
    if(!once('SM'+len+(function(){try{return b2h(rN(this.context.x0,Math.min(len,16)))||'';}catch(e){return '';}}).call(this))) return;
    send({k:'SM3',len:len,head:b2h(rN(this.context.x0,Math.min(len,48))),lr:lr.call(this)});
  }});
  // 7) single-block AES enc/dec (inner layer candidates)
  [OFF.BLK_ENC,OFF.BLK_DEC].forEach(function(o,nm){
    Interceptor.attach(base.add(o),{onEnter:function(a){
      n.blk=(n.blk||0)+1;
      if(!once('BK'+nm)) return;
      send({k:'BLK',w:nm,lr:lr.call(this),x0:b2h(rN(this.context.x0,16)),x1:b2h(rN(this.context.x1,16))});
    }});});
  send({k:'ARMED'});
}
var b=null; Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});
if(b){install(b);} else {
  var dl=Module.findGlobalExportByName?Module.findGlobalExportByName('android_dlopen_ext'):null;
  if(dl)Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readUtf8String();}catch(e){}},
    onLeave:function(){if(b)return;if(this.p&&this.p.indexOf(MOD)>=0){Process.enumerateModules().forEach(function(m){if(m.name===MOD)b=m.base;});if(b)install(b);}}});
  send({k:'WAIT_DLOPEN'});
}
rpc.exports={stats:function(){return n;}};

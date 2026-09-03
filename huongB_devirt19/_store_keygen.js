'use strict';
// STORE-KEYGEN oracle v3 — hook the OLLVM store-key generators directly.
// Hypothesis: the store key is DERIVED at init and held in RAM even though the
// .ms* file is never read on a warm launch. GEN offsets 0x10bbd0 / 0x1182d0.
// We dump args+retval+pointed buffers on enter/leave, dedupe by content, and
// log ALL EINIT(key,iv,keyBytes) so a generator output can be matched to a key.
var MOD='libmetasec_ov.so';
var GEN={ G1:0x10bbd0, G2:0x1182d0 };
var OFF={ EINIT:0x159d60, KSCH:0x1591bc };
var installed=false, preloaded=false;
var einits={}, gseen={}, gcount={G1:0,G2:0}, GCAP=40, log=[];

function b2h(ab){ if(!ab) return null; var u=new Uint8Array(ab),s='';
  for(var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; }
function looksPtr(p){ try{ return !p.isNull() && p.compare(ptr('0x10000'))>0 && p.compare(ptr('0x8000000000'))<0; }catch(e){return false;} }
function rd(p,n){ try{ if(!looksPtr(p)) return null; return b2h(p.readByteArray(n)); }catch(e){return null;} }
function kbnorm(v){ return (v===16||v===24||v===32)?v:16; }

function snapArgs(a,n){ var o=[]; for(var i=0;i<n;i++){ var v=null; try{v=a[i];}catch(e){}
    o.push({raw:v?v.toString():null, mem:rd(v,48)}); } return o; }

function hookGen(base,name,off){
  var A=base.add(off);
  Interceptor.attach(A,{
    onEnter:function(a){ this.name=name; this.args=[];
      for(var i=0;i<8;i++){ var v=null; try{v=a[i];}catch(e){} this.args.push(v); }
      this.enter=[]; for(var j=0;j<8;j++){ this.enter.push(this.args[j]?this.args[j].toString():null); }
      this.memIn=[]; for(var k=0;k<6;k++){ this.memIn.push(rd(this.args[k],48)); }
    },
    onLeave:function(r){
      if(gcount[name]>=GCAP) return;
      var ret=r?r.toString():null; var retMem=rd(r,48);
      var memOut=[]; for(var k=0;k<6;k++){ memOut.push(rd(this.args[k],48)); }
      // signature: dedupe by (ret + all memOut + memIn)
      var sig=name+'|'+ret+'|'+retMem+'|'+memOut.join(',')+'|'+this.memIn.join(',');
      if(gseen[sig]) return; gseen[sig]=1; gcount[name]++;
      var ev={prim:name, args:this.enter, ret:ret, retMem:retMem, memIn:this.memIn, memOut:memOut};
      log.push(ev);
      send({tag:'GEN', name:name, ret:ret, retMem:retMem,
            a:this.enter.slice(0,5), memIn:this.memIn.slice(0,5), memOut:memOut.slice(0,5)});
    }
  });
}

function install(base){
  if(installed) return; installed=true; var A=function(o){return base.add(o);};
  hookGen(base,'G1',GEN.G1);
  hookGen(base,'G2',GEN.G2);
  Interceptor.attach(A(OFF.EINIT),{ onEnter:function(a){
    var kb=kbnorm((function(){try{return a[2].toInt32();}catch(e){return -1;}})());
    var key=rd(a[1],kb), iv=rd(a[3],16); var id=kb+':'+(key||'')+':'+(iv||'');
    if(!einits[id]){ einits[id]=1; send({tag:'EINIT',kb:kb,key:key,iv:iv}); } else einits[id]++; }});
  send({tag:'READY', base:base.toString(), preloaded:preloaded});
}

(function(){
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
  status:function(){ return {installed:installed, preloaded:preloaded,
    g1:gcount.G1, g2:gcount.G2, neinit:Object.keys(einits).length}; },
  dump:function(){ return {gen:log, einits:einits}; }
};

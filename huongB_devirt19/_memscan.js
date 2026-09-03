'use strict';
// Memory scan for known on-disk store ciphertext (stable files). When found in a
// live buffer -> dump surroundings + hunt adjacent plaintext (JSON/ascii). No code hooks.
var needles = (typeof NEEDLES!=='undefined')?NEEDLES:[];
function b2h(ab){if(!ab)return null;var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var h=u[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
function ascii(ab){var u=new Uint8Array(ab),s='';for(var i=0;i<u.length;i++){var c=u[i];s+=(c>=32&&c<=126)?String.fromCharCode(c):'.';}return s;}
function scanAll(pattern){
  var hits=[];
  Process.enumerateRanges('rw-').forEach(function(rg){
    try{ Memory.scanSync(rg.base,rg.size,pattern).forEach(function(m){ hits.push(m.address); }); }catch(e){}
  });
  return hits;
}
rpc.exports={
  scan:function(needleHexList){
    var out=[];
    needleHexList.forEach(function(nh){
      // pattern = first 16 bytes spaced hex
      var b=nh.slice(0,32); var pat=''; for(var i=0;i<b.length;i+=2){pat+=(i?' ':'')+b.substr(i,2);}
      var hits=scanAll(pat);
      var samples=[];
      hits.slice(0,3).forEach(function(a){
        var around=null,txt=null;
        try{ around=b2h(a.sub(64).readByteArray(256)); }catch(e){}
        try{ txt=ascii(a.sub(256).readByteArray(768)); }catch(e){}
        samples.push({addr:a.toString(), around:around, ascii:txt});
      });
      out.push({needle:nh.slice(0,32), count:hits.length, samples:samples});
    });
    return out;
  },
  // scan for ascii marker strings (decrypted plaintext hints)
  scanstr:function(strs){
    var out=[];
    strs.forEach(function(s){
      var pat=''; for(var i=0;i<s.length;i++){var h=s.charCodeAt(i).toString(16);pat+=(i?' ':'')+(h.length<2?'0':'')+h;}
      var hits=scanAll(pat);
      var samples=[];
      hits.slice(0,4).forEach(function(a){ try{ samples.push({addr:a.toString(), ctx:ascii(a.sub(32).readByteArray(400))}); }catch(e){} });
      out.push({str:s, count:hits.length, samples:samples});
    });
    return out;
  }
};
send({k:'READY'});

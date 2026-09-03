'use strict';
var BASE=null;
function hexb(u8){var s='';for(var i=0;i<u8.length;i++){var h=u8[i].toString(16);s+=(h.length<2?'0':'')+h;}return s;}
(function inst(){
  var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)BASE=ms[i].base;
  if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE'});
  var n=0;
  Interceptor.attach(BASE.add(0x9fdac),{onEnter:function(a){
    n++;
    if(n>120) return;
    try{
      var len=a[1].toInt32();
      if(len>=16 && len<=96){
        var buf=Memory.readByteArray(a[0],len);
        if(buf) send({k:'S',n:n,len:len,hex:hexb(new Uint8Array(buf)),lr:'0x'+this.context.lr.sub(BASE).toString(16)});
      }
    }catch(e){}
  }});
  send({k:'READY'});
})();

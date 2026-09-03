'use strict';
var BASE=null;
function asc(u8){var s='';for(var i=0;i<u8.length;i++){var c=u8[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
(function inst(){
  var ms=Process.enumerateModules();for(var i=0;i<ms.length;i++)if(ms[i].name.indexOf('libmetasec')>=0)BASE=ms[i].base;
  if(!BASE){setTimeout(inst,300);return;}
  send({k:'BASE'});
  var n=0, withQuery=0;
  Interceptor.attach(BASE.add(0x9fdac),{onEnter:function(a){
    n++;
    // thử x1 as len
    try{
      var len=a[1].toInt32();
      if(len>20 && len<8192){
        var buf=Memory.readByteArray(a[0],Math.min(len,200));
        if(buf){var u8=new Uint8Array(buf); var s=asc(u8);
          if(s.indexOf('os=')>=0||s.indexOf('device_')>=0||s.indexOf('aid=')>=0){
            withQuery++;
            if(withQuery<=8) send({k:'Q',len:len,lastbyte:new Uint8Array(Memory.readByteArray(a[0].add(len-1),1))[0],head:s.slice(0,80),ctx:a[2].toString()});
          }
        }
      }
    }catch(e){}
  }});
  setInterval(function(){send({k:'CNT',n:n,q:withQuery});},3000);
  send({k:'READY'});
})();

'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
const cnt={sm3:0,closure:0,concat:0,vm:0};
Interceptor.attach(base.add(0xa0748),{onEnter(){cnt.sm3++;}});      // SM3 compression
Interceptor.attach(base.add(0x9bf88),{onEnter(){cnt.closure++;}});  // closure invoker
Interceptor.attach(base.add(0x150348),{onEnter(){cnt.concat++;}});  // concat(query,slot16)
Interceptor.attach(base.add(0x55950),{onEnter(){cnt.vm++;}});       // VM
setInterval(function(){send({t:'CNT',cnt:cnt});},2000);
send({t:'info',msg:'path probe installed'});

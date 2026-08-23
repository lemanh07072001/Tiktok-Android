'use strict';
const SO='libmetasec_ov.so';
const m=Process.findModuleByName(SO);
const base=m.base;
let sm3=0;
Interceptor.attach(base.add(0xa0748),{onEnter(){sm3++;}});
setInterval(function(){send({t:'SM3',count:sm3});},2000);
send({t:'info',msg:'sm3 light installed base='+base});

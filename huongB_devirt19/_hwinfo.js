'use strict';
// Log how the app reads CPU/hardware info: system properties, /proc/cpuinfo, sysconf, uname
const props={}, files={}, syscalls={};
const spg=Module.findGlobalExportByName('__system_property_get');
if(spg)Interceptor.attach(spg,{onEnter(a){try{this.n=a[0].readCString();}catch(e){}},onLeave(){if(this.n)props[this.n]=(props[this.n]||0)+1;}});
const fopenf=Module.findGlobalExportByName('fopen');
if(fopenf)Interceptor.attach(fopenf,{onEnter(a){try{this.n=a[0].readCString();}catch(e){}},onLeave(){if(this.n&&/proc|sys|cpu|mem/i.test(this.n))files[this.n]=(files[this.n]||0)+1;}});
const openf=Module.findGlobalExportByName('open')||Module.findGlobalExportByName('openat');
if(openf)Interceptor.attach(openf,{onEnter(a){try{this.n=(Module.findGlobalExportByName('openat')===openf?a[1]:a[0]).readCString();}catch(e){}},onLeave(){if(this.n&&/proc|sys|cpu|mem/i.test(this.n))files[this.n]=(files[this.n]||0)+1;}});
const sc=Module.findGlobalExportByName('sysconf');
if(sc)Interceptor.attach(sc,{onEnter(a){syscalls['sysconf('+a[0].toInt32()+')']=(syscalls['sysconf('+a[0].toInt32()+')']||0)+1;}});
const un=Module.findGlobalExportByName('uname');
if(un)Interceptor.attach(un,{onEnter(){syscalls['uname']=(syscalls['uname']||0)+1;}});
const si=Module.findGlobalExportByName('sysinfo');
if(si)Interceptor.attach(si,{onEnter(){syscalls['sysinfo']=(syscalls['sysinfo']||0)+1;}});
setInterval(function(){send({t:'HW',props:props,files:files,syscalls:syscalls});},3000);
send({t:'info',msg:'hwinfo installed'});

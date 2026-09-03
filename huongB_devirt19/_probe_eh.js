// _probe_eh.js — Isolation probe: does installing Process.setExceptionHandler (alone, post-cold-start) kill
// the app? No memcpy hooks, no watchpoints. Install handler at first slot16 driver call after an 18s gate.
// If the process survives to end => handler is safe; the death in _wp_tag is from memcpy-hot or arming.
// If it dies shortly after 'HANDLER' => the exception handler itself trips TikTok anti-tamper / a conflict.
'use strict';
const SO='libmetasec_ov.so';
const DRV=0x9fdac;
let base=null, lo=null, hi=null, safe=false, set=false, segv=0;
function install(){
  const m=Process.findModuleByName(SO); if(!m)return false; base=m.base; lo=base; hi=base.add(m.size);
  send({t:'info', base:base.toString()});
  Interceptor.attach(base.add(DRV), { onEnter(args){ if(set||!safe) return; const c=this.context;
    let w1=null; try{ w1=parseInt(c.x1.toString())&0xffffffff; }catch(e){} if(w1!==16) return;
    set=true;
    Process.setExceptionHandler(function(d){ if(d.type==='access-violation'){ segv++; return false; } return false; });
    send({t:'HANDLER', note:'exception handler installed, no hooks/WP'}); }});
  send({t:'ready'}); return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),
  {onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});
setTimeout(function(){ safe=true; send({t:'safe'}); }, 18000);
setInterval(function(){ send({t:'mon', safe:safe, set:set, segv:segv}); }, 3000);

'use strict';
const SO='libmetasec_ov.so', MEMCPY=0x172a50;
const cm = new CModule(`
#include <gum/gumstalker.h>
#include <stdint.h>
extern volatile uint32_t rc;
volatile uint32_t rc = 0;
static void cb (GumCpuContext * c, gpointer u){ rc++; }   // minimal, touches nothing risky
void transform (GumStalkerIterator * it, GumStalkerOutput * out, gpointer u){
  const cs_insn * insn;
  while (gum_stalker_iterator_next (it, &insn)){
    const char * mn = insn->mnemonic;
    if (mn[0]=='s' && mn[1]=='t') gum_stalker_iterator_put_callout (it, cb, 0, 0);
    gum_stalker_iterator_keep (it);
  }
}
`, {});
let base=null,lo,hi,done=false;
function install(){
  const m=Process.findModuleByName(SO); if(!m) return false; base=m.base; lo=base; hi=base.add(m.size);
  Interceptor.attach(base.add(MEMCPY),{onEnter(a){
    if(done) return; if(a[2].toInt32()!==16) return; let ra=null; try{ra=this.returnAddress;}catch(e){}
    if(!ra||ra.compare(lo)<0||ra.compare(hi)>=0||ra.sub(base).toString(16)!=='a0440') return;
    done=true; const tid=this.threadId;
    try{ Stalker.follow(tid,{transform:cm.transform}); send({t:'ok',msg:'followed '+tid}); }
    catch(e){ send({t:'err',msg:''+e}); done=false; return; }
    setTimeout(function(){ try{Stalker.unfollow(tid);Stalker.flush();}catch(e){} send({t:'cnt',rc:cm.rc.readU32()}); },1500);
  }});
  send({t:'info',msg:'iso installed'});
  return true;
}
if(Process.findModuleByName(SO)) install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(SO)>=0)install();}});

'use strict';
const SO='libmetasec_ov.so';
let mod=null;
function libc(){ return Process.getModuleByName('libc.so'); }
function exp(n){ try{const p=libc().findExportByName(n); if(p)return p;}catch(e){} try{return Module.getGlobalExportByName(n);}catch(e){} return null; }
const seen={}; let cnt=0;
function interesting(s){
  if(!s) return false;
  // app data dir + any store-ish token
  if(s.indexOf('com.zhiliaoapp')>=0) return true;
  if(/\bms[psf]|mss|\/ss\/|\/\.ss|argus|device_?register|\.dat\b|libmetasec/i.test(s)) return true;
  return false;
}
function hookOpen(fn,idx){ if(!fn) return; Interceptor.attach(fn,{
  onEnter(a){ try{this.p=a[idx].readUtf8String();}catch(e){this.p=null;} },
  onLeave(r){ const fd=r.toInt32(); if(this.p && interesting(this.p)){ if(!seen[this.p]){ seen[this.p]=1; cnt++; if(cnt<=300) send({t:'PATH', fd:fd, path:this.p}); } } }
});}
hookOpen(exp('openat'),1); hookOpen(exp('open'),0);
send({t:'ready'});

// read the store-prefix global once SO is loaded
let tries=0;
const iv=setInterval(()=>{ tries++;
  if(!mod){ mod=Process.findModuleByName(SO); }
  if(mod){
    clearInterval(iv);
    try{
      const g=mod.base.add(0x1f2d70);
      let info={base:mod.base.toString(), size:mod.size};
      try{ const ptr=g.readPointer(); info.ptr=ptr.toString();
        try{ info.str=ptr.readUtf8String(); }catch(e){ info.str='ERR:'+e; }
      }catch(e){ info.ptrErr=''+e; }
      // also dump 64 bytes raw around the global
      try{ const b=g.readByteArray(32); const u=new Uint8Array(b); let h='';for(let i=0;i<u.length;i++)h+=('0'+u[i].toString(16)).slice(-2); info.raw=h; }catch(e){ info.rawErr=''+e; }
      send({t:'GLOBAL', info:info});
    }catch(e){ send({t:'GLOBAL', err:''+e}); }
  }
  if(tries>200) clearInterval(iv);
}, 200);

import frida,sys,os,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
PKG="com.zhiliaoapp.musically"
JS=r"""
const MSEC='libmetasec_ov.so'; const KREAD=0x1280c0, KT=0x19b540;
function install(){
  const m=Process.findModuleByName(MSEC); if(!m)return false; const base=m.base;
  // verify instruction bytes at runtime
  let ib=''; try{const u=new Uint8Array(base.add(KREAD).readByteArray(4));for(const x of u)ib+=('0'+x.toString(16)).slice(-2);}catch(e){}
  send({t:'info',msg:'base='+base+' K0='+base.add(KT)+' instr@0x1280c0='+ib});
  let n=0;
  Interceptor.attach(base.add(KREAD),{onEnter(){
    if(n<8){ const c=this.context; const x9=c.x9; const off=x9?x9.sub(base).toString(16):'?';
      send({t:'fire',n:n,x9:x9?x9.toString():null,x9off:'0x'+off,x8:c.x8?c.x8.toString():null}); }
    n++;
  }});
  setTimeout(()=>send({t:'count',n:n}),18000);
  return true;
}
if(Process.findModuleByName(MSEC))install();
else Interceptor.attach(Module.findGlobalExportByName('android_dlopen_ext'),{onEnter(a){try{this.p=a[0].readCString();}catch(e){}},onLeave(){if(this.p&&this.p.indexOf(MSEC)>=0)install();}});
"""
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid);sc=s.create_script(JS)
def om(m,d):
    if m.get("type")=="error":print("[ERR]",m.get("description"));return
    p=m.get("payload") or {}
    if p.get("t")=="info":print("[*]",p["msg"],flush=True)
    elif p.get("t")=="fire":print("  fire#%d x9=%s (off %s) x8=%s"%(p["n"],p["x9"],p["x9off"],p["x8"]),flush=True)
    elif p.get("t")=="count":print("[*] total fires in 18s: %d"%p["n"],flush=True)
sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(21)
try:s.detach()
except:pass

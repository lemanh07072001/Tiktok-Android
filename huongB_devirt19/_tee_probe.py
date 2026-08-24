# ROOT-CAUSE probe (live phone): is the PSK/slot16/#18/#19 path TEE-rooted or software-only?
#  + confirm #24 attestation source = MediaDrm.getPropertyByteArray("deviceUniqueId") + capture DUID.
# Read-only hooks. attach to musically via msnkd:47119.
import sys, os, json, time, frida
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
PKG="com.zhiliaoapp.musically"; HOST=os.environ.get("FRIDA_HOST","127.0.0.1:47119")
RUN=int(os.environ.get("RUN_SEC","45"))

JS=r"""
const LIB='libmetasec_ov.so';
let mm=Process.findModuleByName(LIB); let mbase=mm?mm.base:null, mend=mm?mm.base.add(mm.size):null;
send({t:'info',msg: mm? ('metasec '+mbase+' size=0x'+mm.size.toString(16)) : 'metasec NOT loaded'});
function inMeta(a){ try{return mbase && a.compare(mbase)>=0 && a.compare(mend)<0;}catch(e){return false;} }
function metaOnStack(ctx){ try{ const bt=Thread.backtrace(ctx, Backtracer.FUZZY); for(const f of bt){ if(inMeta(f)) return f; } }catch(e){} return null; }
function exp(mod,name){ try{ const m=Process.getModuleByName(mod); const e=m.findExportByName(name); if(e) return e; }catch(e){}
  try{ return Module.getExportByName(mod,name); }catch(e){}
  try{ return Module.findExportByName(mod,name); }catch(e){} return null; }

// ---- openat: log paths; for TEE/keystore/drm/mediadrm paths do a metasec-backtrace attribution ----
const seen={};
const INTEREST=/tee|qseecom|mediadrm|widevine|keymaster|keystore|gatekeeper|hwbinder|secure|/i;
const oa=exp('libc.so','openat') || exp('libc.so','__openat');
send({t:'info',msg:'openat='+oa});
if(oa) Interceptor.attach(oa,{ onEnter(a){
  try{ const p=a[1].readCString(); if(!p) return;
    const hot=INTEREST.test(p) || /drm/i.test(p);
    if(hot){ const mf=metaOnStack(this.context); const key=p+'|'+(mf?'META':'other');
      if(!seen[key]){ seen[key]=1; send({t:'OPEN_HOT', path:p, metasec: mf? mf.toString():null}); } }
    else { if(!seen[p]){ seen[p]=1; if(Object.keys(seen).length<400) send({t:'open', path:p}); } }
  }catch(e){}
}});

// ---- Java: MediaDrm.getPropertyByteArray -> confirm #24 deviceUniqueId source + capture DUID ----
try{
 Java.perform(function(){
   const MD=Java.use('android.media.MediaDrm');
   MD.getPropertyByteArray.implementation=function(name){
     const r=this.getPropertyByteArray(name);
     try{ let hex=''; if(r){ const b=Java.array('byte',r); const n=Math.min(b.length,64); for(let i=0;i<n;i++){hex+=('0'+((b[i])&0xff).toString(16)).slice(-2);} }
       send({t:'MEDIADRM_PROP', name:name, len: r?r.length:0, hex:hex, metasec: !!metaOnStack(this.context)}); }catch(e){}
     return r;
   };
   send({t:'info',msg:'MediaDrm.getPropertyByteArray hooked'});
 });
}catch(e){ send({t:'info',msg:'Java hook err '+e}); }
"""

dev=frida.get_device_manager().add_remote_device(HOST)
procs=[p for p in dev.enumerate_processes() if p.name==PKG or ("music" in p.name.lower())]
sess=None
for p in procs:
    try:
        s=dev.attach(p.pid); sc=s.create_script(JS);
        msgs=[]
        def on(m,d,_msgs=msgs):
            if m.get("type")=="send": _msgs.append(m["payload"])
            else: print("[frida]",m)
        sc.on("message",on); sc.load(); sess,script,MSGS=s,sc,msgs
        print("[*] attached pid=%d (%s)"%(p.pid,p.name),flush=True); break
    except Exception as e:
        print("[skip] pid",p.pid,e)
if not sess: print("[!] cannot attach"); sys.exit(1)

# nudge app to foreground/feed so heartbeat+device_register signing fires
try:
    import subprocess
    subprocess.run(['adb','shell','am','start','-n','com.zhiliaoapp.musically/com.ss.android.ugc.aweme.main.MainActivity'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
except Exception: pass
print("[*] observing %ds (foreground feed -> signing fires)..."%RUN,flush=True)
time.sleep(RUN)

opens=[m for m in MSGS if m.get("t")=="open"]
hot=[m for m in MSGS if m.get("t")=="OPEN_HOT"]
md=[m for m in MSGS if m.get("t")=="MEDIADRM_PROP"]
ioc=[m for m in MSGS if m.get("t")=="IOCTL_META"]
info=[m for m in MSGS if m.get("t")=="info"]
print("\n===== RESULT =====")
for m in info: print("[info]",m["msg"])
print("\n[HOT paths tee/drm/keystore] (%d):"%len(hot))
for m in hot: print("   %-55s metasec_frame=%s"%(m["path"], m["metasec"]))
print("\n[metasec ioctl count] %d"%len(ioc))
print("\n[MediaDrm.getPropertyByteArray] (%d):"%len(md))
for m in md: print("   name=%-18s len=%d metasec_stack=%s hex=%s"%(m["name"],m["len"],m["metasec"],m["hex"]))
# summarize metasec-attributed hot opens
meta_hot=[m for m in hot if m.get("metasec")]
print("\n[SUMMARY] metasec-attributed TEE/DRM/keystore opens: %d"%len(meta_hot))
for m in meta_hot: print("   ->",m["path"])
print("[SUMMARY] total distinct non-hot opens seen: %d (sample):"%len(opens))
for m in opens[:25]: print("     ",m["path"])

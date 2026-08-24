# DECISIVE TEE-vs-software test: does libmetasec_ov NATIVELY pull MediaDrm/keystore/TEE at runtime?
#  Static: no AMediaDrm/keystore/keymaster/widevine/binder import; only escape hatch = npth_dlopen/npth_dlsym.
#  Here: hook npth_dlopen/npth_dlsym + metasec-range ioctl, then FORCE a device_register sign (base+SIGN_OFF)
#  so the full report (incl #24 attestation collection) is built. Log every lib/symbol/ioctl libmetasec asks for.
import sys, os, json, time, frida
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
PKG="com.zhiliaoapp.musically"; HOST=os.environ.get("FRIDA_HOST","127.0.0.1:47119")
SIGN_OFF=os.environ.get("MS_SIGN_OFF","0x9ecc0")

JS=r"""
const LIB='libmetasec_ov.so'; const SIGN_OFF=%s;
let mm=Process.findModuleByName(LIB); let mbase=mm?mm.base:null, mend=mm?mm.base.add(mm.size):null;
send({t:'info',msg: mm?('metasec '+mbase+' size=0x'+mm.size.toString(16)):'metasec NOT loaded'});
function inMeta(a){ try{return mbase&&a.compare(mbase)>=0&&a.compare(mend)<0;}catch(e){return false;} }
function fromMeta(ctx){ try{ const bt=Thread.backtrace(ctx,Backtracer.FUZZY); for(const f of bt){ if(inMeta(f)) return f; } }catch(e){} return null; }

// ---- npth_dlopen / npth_dlsym (the ONLY runtime lib-load hatch) ----
function hookExp(name, argIdxStr){
  let a=null;
  try{ const m=Process.getModuleByName('libnpth_dl.so'); a=m.findExportByName(name);}catch(e){}
  if(!a){ try{ const m2=Process.getModuleByName(LIB); a=m2.findExportByName(name);}catch(e){} }
  send({t:'info',msg:name+'='+a});
  if(!a) return;
  Interceptor.attach(a,{ onEnter(args){
    try{ let s=null; try{s=args[argIdxStr].readCString();}catch(e){}
      const mf=fromMeta(this.context);
      send({t:'DLCALL', fn:name, arg:s, fromMeta: mf?mf.toString():null});
    }catch(e){}
  }});
}
hookExp('npth_dlopen', 0);
hookExp('npth_dlsym', 1);   // dlsym(handle, symName) -> arg1 is the symbol name

function libcExp(name){ try{ return Process.getModuleByName('libc.so').findExportByName(name);}catch(e){return null;} }

// ---- ioctl from metasec range: catch any TEE/binder/drm device ioctl ----
const seenfd={};
const ioctl=libcExp('ioctl');
send({t:'info',msg:'ioctl='+ioctl});
if(ioctl) Interceptor.attach(ioctl,{ onEnter(a){
  try{ const mf=fromMeta(this.context); if(!mf) return;
    const fd=a[0].toInt32(); const req=a[1].toInt32()>>>0;
    let link='?'; try{ link=File.readlink? File.readlink('/proc/self/fd/'+fd):'?'; }catch(e){}
    const key=fd+'|'+req;
    if(!seenfd[key]){ seenfd[key]=1;
      send({t:'IOCTL_META', fd:fd, req:'0x'+req.toString(16), path:link, fromMeta:mf.toString()});
    }
  }catch(e){}
}});

// ---- openat from metasec range (device nodes during report build) ----
const oa=libcExp('openat')||libcExp('__openat');
if(oa) Interceptor.attach(oa,{ onEnter(a){
  try{ const p=a[1].readCString(); if(!p) return; const mf=fromMeta(this.context);
    if(mf) send({t:'OPEN_META', path:p, fromMeta:mf.toString()});
  }catch(e){}
}});

// ---- sign trigger ----
let sign=null;
function initSign(){ if(!mm) return false; sign=new NativeFunction(mbase.add(SIGN_OFF),'pointer',['pointer','pointer']); return true; }
rpc.exports={ doSign(url,hdr){ if(!sign&&!initSign()) throw new Error('no metasec');
  const u=Memory.allocUtf8String(url), h=Memory.allocUtf8String(hdr);
  const r=sign(u,h); return r.isNull()?null:r.readUtf8String(); } };
send({t:'info',msg:'hooks armed'});
""" % SIGN_OFF

dev=frida.get_device_manager().add_remote_device(HOST)
procs=[p for p in dev.enumerate_processes() if p.name==PKG]
sess=script=None; MSGS=[]
for p in procs:
    try:
        s=dev.attach(p.pid); sc=s.create_script(JS)
        def on(m,d):
            if m.get("type")=="send": MSGS.append(m["payload"])
            else: print("[frida]",m)
        sc.on("message",on); sc.load(); sess,script=s,sc
        print("[*] attached pid=%d (%s)"%(p.pid,p.name),flush=True); break
    except Exception as e:
        print("[skip] pid",p.pid,e)
if not sess: print("[!] cannot attach"); sys.exit(1)

time.sleep(1.0)
# force a device_register sign -> full report build (incl #24 collection path)
turl="https://api-boot.tiktokv.com/service/2/device_register/?device_platform=android&aid=1233&version_code=2024505040"
thdr=("x-ss-stub\r\n01205F31B47EC9C72AB1A5555960AA63\r\ncontent-type\r\napplication/json; charset=utf-8\r\n"
      "x-ss-req-ticket\r\n%d\r\nsdk-version\r\n2\r\npassport-sdk-version\r\n1\r\n"
      "user-agent\r\ncom.zhiliaoapp.musically/2024505040" % int(time.time()*1000))
print("[*] forcing device_register sign to build full report...",flush=True)
try:
    out=script.exports_sync.do_sign(turl,thdr)
    xa=""
    if out:
        for i,ln in enumerate(out.replace("\r\n","\n").split("\n")):
            if ln.strip().lower()=="x-argus" and i>=0: pass
        # crude X-Argus len
        parts=out.replace("\r\n","\n").split("\n")
        for i,k in enumerate(parts[:-1]):
            if k.strip().lower()=="x-argus": xa=parts[i+1].strip()
    print("[*] sign done, X-Argus len=%d"%len(xa),flush=True)
except Exception as e:
    print("[*] sign err",e,flush=True)
time.sleep(1.5)

dl=[m for m in MSGS if m.get("t")=="DLCALL"]
ic=[m for m in MSGS if m.get("t")=="IOCTL_META"]
op=[m for m in MSGS if m.get("t")=="OPEN_META"]
info=[m for m in MSGS if m.get("t")=="info"]
print("\n===== RESULT =====")
for m in info: print("[info]",m["msg"])
print("\n[npth_dlopen/dlsym calls FROM metasec] (%d):"%len([x for x in dl if x.get("fromMeta")]))
for m in dl: print("   %-14s arg=%-40s fromMeta=%s"%(m["fn"],str(m.get("arg")),m.get("fromMeta")))
print("\n[metasec ioctl] (%d):"%len(ic))
for m in ic[:40]: print("   fd=%s req=%s"%(m["fd"],m["req"]))
print("\n[metasec openat device nodes] (%d):"%len(op))
for m in op[:40]: print("   %s"%m["path"])
# verdict
drmish=[m for m in dl if m.get("arg") and any(k in str(m["arg"]).lower() for k in ["drm","media","widevine","wv","keystore","keymaster","oemcrypto","tee","qsee","attest"])]
print("\n[VERDICT] metasec-native DRM/TEE/keystore lib/sym loads: %d"%len(drmish))
for m in drmish: print("   ->",m["fn"],m.get("arg"))

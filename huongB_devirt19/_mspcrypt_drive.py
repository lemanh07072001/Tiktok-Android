import frida,subprocess,time,json,base64,os
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
OVD="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
def raw(*a): return subprocess.run([ADB,"shell"]+list(a),capture_output=True,text=True).stdout
def disk():
    names=[x for x in sh("ls","-1A",OVD).split() if x.startswith(".ms")]
    return {n:base64.b64decode(sh("base64",f"{OVD}/{n}").strip().replace("\n","")).hex() for n in names}
sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity")
t0=time.time()
while time.time()-t0<30:
    o=sh("pidof",PKG).strip()
    if o and time.time()-t0>=8: break
    time.sleep(0.3)
pid=int(o.split()[0]); print("attach pid",pid,"t=%.1f"%(time.time()-t0),flush=True)
disk_before=disk()
dev=frida.get_usb_device(timeout=10)
sess=None
for _try in range(4):
    try: sess=dev.attach(pid); break
    except Exception as _e:
        print("attach retry",_try,_e,flush=True); time.sleep(2)
if sess is None: print("ATTACH FAILED"); os._exit(1)
def on(m,d):
    if m.get("type")=="send" and m["payload"].get("k") in("HOOK","ERR","READY"): print(" ",m["payload"],flush=True)
    elif m.get("type")=="error": print(" ERR",m.get("description"),flush=True)
scr=sess.create_script(open("_mspcrypt.js").read()); scr.on("message",on); scr.load()
print("collecting 60s (natural write ~t20-40 + swipes)...",flush=True)
t1=time.time(); nxt=0; phase=0
while time.time()-t1<60:
    e=int(time.time()-t1)
    if e>=nxt:
        subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True)
        # rotate triggers to force store WRITE without touching login
        phase+=1; nxt=e+6
    time.sleep(1)
try: caps=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex,flush=True); caps=[]
disk_after=disk()
json.dump({"caps":caps,"before":disk_before,"after":disk_after},open("_mspcrypt_out.json","w"),indent=1)
print("=== EVENTS ===",len(caps),flush=True)
# did any store file change (write happened)?
changed=[n for n in disk_after if disk_before.get(n)!=disk_after.get(n)]
print("store files CHANGED this run:",changed,flush=True)
# match: any captured buffer == on-disk ct (before or after)?
def ck(h):
    if not h: return ""
    for src,dd in (("aft",disk_after),("bef",disk_before)):
        for n,dh in dd.items():
            if dh and len(dh)>=16 and dh[:24] in h: return f"{src}:{n[:16]}"
    return ""
hits=0
for c in caps:
    if c.get("fn")=="BLR": continue
    for tag in("pre","post"):
        for b in c.get(tag,[]):
            m=ck(b.get("hex"))
            if m: print(f"  CT-MATCH {c['fn']} {tag} {b['t']} -> {m}  hex={b['hex'][:48]}",flush=True); hits+=1
print("ct-match hits:",hits,flush=True)
os._exit(0)

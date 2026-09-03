import frida,subprocess,time,json,base64
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
OVD="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
def disk():
    names=[x for x in sh("ls","-1A",OVD).split() if x.startswith(".ms")]
    return {n:base64.b64decode(sh("base64",f"{OVD}/{n}").strip().replace("\n","")).hex() for n in names}
sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity")
t0=time.time()
while time.time()-t0<30:
    o=sh("pidof",PKG).strip()
    if o and time.time()-t0>=8: break
    time.sleep(0.4)
pid=int(o.split()[0]); print("attach pid",pid,"t=%.1f"%(time.time()-t0))
dev=frida.get_usb_device(timeout=10); sess=dev.attach(pid)
def on(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.get("k") in("PRO","HOOKED","HOOKERR","READY"): print(" ",json.dumps(p)[:160])
    elif m.get("type")=="error": print(" ERR",m.get("description"))
scr=sess.create_script(open("_argdump.js").read()); scr.on("message",on); scr.load()
print("collecting 50s...")
t1=time.time(); nxt=0
while time.time()-t1<50:
    e=int(time.time()-t1)
    if e>=nxt: subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True); nxt=e+7
    time.sleep(1)
try: caps=scr.exports_sync.dump()
except Exception as ex: print("dump exc",ex); caps=[]
d=disk()
json.dump({"caps":caps,"disk":d},open("_argdump_out.json","w"),indent=1)
print("=== HITS ===", len(caps))
# print any arg buffer that looks like plaintext (printable) or matches a disk ciphertext
for c in caps[:40]:
    print("\n@@", c["off"], "ret",c["ret"])
    for tag,args in [("in",c["pre"]),("out",c["post"])]:
        for a in args:
            if a.get("str") or (a.get("hex") and c["off"]):
                pr=""
                if a.get("hex"):
                    b=bytes.fromhex(a["hex"]); pr=sum(1 for x in b if 32<=x<=126)/len(b)
                mark=""
                if a.get("hex"):
                    for n,dh in d.items():
                        if dh and len(dh)>=16 and dh[:24] in a["hex"]: mark=" <<CT="+n[:16]
                if a.get("str") or (isinstance(pr,float) and pr>0.6) or mark:
                    print(f"   {tag} x{a['i']} pr={pr if isinstance(pr,float) else '':.2s} str={a.get('str')} hex={str(a.get('hex'))[:64]}{mark}")
sess.detach()

import frida,subprocess,time,json,sys
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"; PKG="com.zhiliaoapp.musically"
OVD="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
def sh(*a): return subprocess.run([ADB,"shell","su","0"]+list(a),capture_output=True,text=True).stdout
import base64
def disk():
    names=[x for x in sh("ls","-1A",OVD).split() if x.startswith(".ms")]
    out={}
    for n in names:
        b=base64.b64decode(sh("base64",f"{OVD}/{n}").strip().replace("\n",""))
        out[n]=b.hex()
    return out
d=disk()
# stable/all ciphertext needles (>=16B)
needles=[h for n,h in d.items() if h and len(h)>=32]
print("needles:",[ (n[:16],len(h)//2) for n,h in d.items() if h and len(h)>=32])
sh("am","force-stop",PKG); time.sleep(1)
sh("am","start","-n",f"{PKG}/com.ss.android.ugc.aweme.splash.SplashActivity")
t0=time.time()
while time.time()-t0<30:
    o=sh("pidof",PKG).strip()
    if o and time.time()-t0>=6: break
    time.sleep(0.4)
pid=int(o.split()[0]); print("attach pid",pid,"t=%.1f"%(time.time()-t0))
dev=frida.get_usb_device(timeout=10); sess=dev.attach(pid)
def on(m,dd):
    if m.get("type")=="send": print(" msg",m["payload"])
    elif m.get("type")=="error": print(" ERR",m.get("description"))
scr=sess.create_script(open("_memscan.js").read()); scr.on("message",on); scr.load()
found={}
for i in range(24):  # ~48s, scan every 2s
    subprocess.run([ADB,"shell","input","swipe","540","1400","540","400","120"],capture_output=True)
    try: res=scr.exports_sync.scan(needles)
    except Exception as e: print("scan exc",e); break
    for r in res:
        if r["count"]>0 and r["needle"] not in found:
            found[r["needle"]]=r
            print(f"  [t{i*2}s] FOUND ct {r['needle']} x{r['count']}")
            for s in r["samples"]:
                print("     @",s["addr"]," ascii:",repr(s["ascii"][:160]))
    time.sleep(2)
# also scan for plaintext markers
try:
    strs=scr.exports_sync.scanstr(["mssdk_setting","sdi_v2","mssdk","vmp_","{\"","device_id"])
    print("=== plaintext marker scan ===")
    for r in strs:
        print(f"  '{r['str']}' x{r['count']}")
        for s in r.get("samples",[])[:2]: print("     ",repr(s.get("ctx","")[:120]))
except Exception as e: print("scanstr exc",e)
json.dump({"found":found,"disk":d},open("_memscan_out.json","w"),indent=1)
print("=== DONE ct-needles found:",list(found.keys()))
sess.detach()

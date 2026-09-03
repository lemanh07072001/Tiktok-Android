import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
POOL=["8ca462427dbfb3f3d431621b14f496ff","46c03b52742b3f2615a3abdf1636b754","9a6b1808e00bd930275f06ee5b776c88","0e817e15c7f71685fd55d6a55d1c0c85"]
dm=frida.get_device_manager(); dev=dm.add_remote_device("127.0.0.1:47119")
pid=dev.spawn([PKG]); print("[*] spawned",pid,flush=True); sess=dev.attach(pid)
sc=sess.create_script(open("_scan_slot16.js").read()); sc.load(); dev.resume(pid)
time.sleep=__import__("time").sleep
allhits=[]
for w in range(8):
    time.sleep(6)
    try: r=sc.exports_sync.scan(POOL)
    except Exception as e: print("[scan err]",e,flush=True); continue
    print("[scan @%ds] %d hits"%(6*(w+1),len(r)),flush=True)
    if r:
        allhits=r
        for h in r[:24]: print("   %s @ %s  region=%s"%(h["slot"][:12],h["addr"],h["region"]),flush=True)
        break
json.dump(allhits,open("_scan_out.json","w"),indent=1)
print("[DONE] hits=%d"%len(allhits),flush=True)

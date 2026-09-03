import frida,json,time,sys,subprocess
from collections import Counter
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 22
subprocess.run(["adb","shell","am","force-stop",PKG],capture_output=True)
time.sleep(1.0)
dev=frida.get_usb_device(timeout=10)
pid=None
for att in range(4):
    try:
        pid=dev.spawn([PKG]); print("spawned pid",pid); break
    except frida.TimedOutError:
        print("spawn timeout attempt",att)
        # recover: frida may have created the suspended proc despite timeout
        for p in dev.enumerate_processes():
            if p.name==PKG or PKG in p.name:
                pid=p.pid; print("recovered pid",pid); break
        if pid: break
        time.sleep(2)
if pid is None:
    print("SPAWN FAILED after retries"); sys.exit(2)
ses=dev.attach(pid)
scr=ses.create_script(open("_store_key_grab.js").read())
def on(m,d):
    if m['type']=='send': print("MSG",m['payload'])
    else: print("ERR",m.get('stack') or m)
scr.on('message',on); scr.load()
try: dev.resume(pid)
except Exception as e: print("resume note:",e)
print("collecting %ds ..."%DUR); time.sleep(DUR)
data=scr.exports_sync.dump()
json.dump(data,open("_grab_out.json","w"))
print("TOTAL",len(data),dict(Counter(e['t'] for e in data)))
try: ses.detach()
except: pass

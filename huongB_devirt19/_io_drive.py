#!/usr/bin/env python3
import sys, time, json, subprocess, frida
PKG="com.zhiliaoapp.musically"
LAUNCHER="com.zhiliaoapp.musically/com.ss.android.ugc.aweme.splash.SplashActivity"
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"
SECS=int(sys.argv[1]) if len(sys.argv)>1 else 40
ATTACH_AT=int(sys.argv[2]) if len(sys.argv)>2 else 5
JS=open("_store_io_trace.js").read()
def adb(*a,t=15):
    try: return subprocess.run([ADB]+list(a),capture_output=True,text=True,timeout=t)
    except Exception as e:
        class R: stdout="";stderr="ERR"+str(e)
        return R()
def pidof():
    r=adb("shell","su","0","pidof",PKG,t=8)
    for tok in (r.stdout or "").replace("\r","").split():
        if tok.isdigit(): return int(tok)
    return None
msgs={"OPEN":0,"WRITE":0,"READ":0,"READY":0,"NOFN":0}
dead={"v":False}
def on_msg(m,d):
    if m.get("type")=="send":
        p=m["payload"]; tag=p.get("tag")
        if tag in msgs: msgs[tag]+=1
        if tag=="READY": print("  <READY base=%s>"%p.get("base"))
        if tag=="NOFN": print("  <NOFN %s>"%p.get("fn"))
        if tag=="OPEN": print("  <OPEN fd=%s store=%s>"%(p.get("fd"),p.get("store")))
        if tag=="WRITE": print("  ***WRITE store=%s len=%s metaOff=%s head=%s***"%(p.get("store"),p.get("len"),p.get("metaOff"),(p.get("head") or "")[:24]))
        if tag=="READ": print("  <READ store=%s len=%s head=%s>"%(p.get("store"),p.get("len"),(p.get("head") or "")[:24]))
    elif m.get("type")=="error": print("  JS-ERR",m.get("description"))
def on_det(r,*a): dead["v"]=True; print("  !! detached",r)
print("force-stop + cold launch")
adb("shell","su","0","am","force-stop",PKG); time.sleep(1)
t0=time.time(); adb("shell","su","0","am","start","-n",LAUNCHER)
dev=frida.get_usb_device(timeout=10); pid=None
while time.time()-t0<30:
    time.sleep(0.4); pid=pidof()
    if pid and (time.time()-t0)>=ATTACH_AT: break
if not pid: print("FATAL no pid"); sys.exit(1)
print("attach pid=%d at ~%.1fs"%(pid,time.time()-t0))
sess=dev.attach(pid); sess.on("detached",on_det)
sc=sess.create_script(JS); sc.on("message",on_msg); sc.load()
print("collecting %ds"%SECS)
tc=time.time(); nud=0
while time.time()-tc<SECS:
    time.sleep(3)
    if dead["v"]: break
    if nud<2: adb("shell","input","swipe","540","1400","540","500","200"); nud+=1
    try: st=sc.exports_sync.status()
    except Exception: st={}
    print("  t%02d %s counts=%s"%(int(time.time()-tc),st,msgs))
try: data=sc.exports_sync.dump()
except Exception as e: data=[]; print("dump err",e)
json.dump(data,open("_io_out.json","w"),indent=1)
print("EVENTS=%d OPEN=%d WRITE=%d READ=%d -> _io_out.json"%(len(data),msgs['OPEN'],msgs['WRITE'],msgs['READ']))

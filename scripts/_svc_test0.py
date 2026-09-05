import frida,sys,time,json
PKG="com.zhiliaoapp.musically"; DUR=45
JS=r"""
var TARGET="libmetasec_ov.so";var done=false;
var iv=setInterval(function(){if(done)return;var m=Process.findModuleByName(TARGET);if(m){done=true;clearInterval(iv);send({tag:'info',msg:'MS loaded base='+m.base+' (NO hooks)'});}},20);
send({tag:'info',msg:'waiting (zero hooks)'});
setInterval(function(){send({tag:'tick'});},10000);
"""
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="tick":print("[tick]",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (ZERO hooks control)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
print("[*] done (detached, NOT killed)",flush=True)

import frida,sys,time
try: sys.stdout.reconfigure(encoding="utf-8",errors="replace")
except: pass
JS=r"""
setTimeout(function(){
  const libs=Process.enumerateModules().filter(m=>/boringssl|crypto|metasec|sscronet/i.test(m.name));
  libs.forEach(m=>{
    const ex=m.enumerateExports().filter(e=>/SHA256|SHA512|MD5|SHA1|HMAC|EVP_Digest|SM3/i.test(e.name));
    send({lib:m.name, base:m.base.toString(), n:ex.length, ex:ex.slice(0,24).map(e=>e.name)});
  });
},1500);
"""
dev=frida.get_usb_device(timeout=10)
p=next((x for x in dev.enumerate_processes() if "musically" in x.name or "tiktok" in x.name.lower()),None)
if not p: print("app not running - spawning"); pid=dev.spawn(["com.zhiliaoapp.musically"]); s=dev.attach(pid); dev.resume(pid); import time as t; t.sleep(3)
else: print("attach",p.pid,p.name); s=dev.attach(p.pid)
sc=s.create_script(JS)
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"]; print("\n[%s] base=%s crypto-exports=%d"%(p["lib"],p["base"],p["n"]));[print("   ",e) for e in p["ex"]]
    elif m.get("type")=="error": print("[ERR]",m.get("description"))
sc.on("message",om);sc.load();time.sleep(3.5)
try:s.detach()
except:pass

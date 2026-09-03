#!/usr/bin/env python3
# Attach app mod 45.9.3 DANG CHAY, hook MS.b Java, bat keva 7632 THẬT (GET ret) + identity cmds.
# Attach (khong spawn) -> JVM ready -> raw Java.perform OK. Trigger swipe de sign -> MS.b keva GET.
import frida, time, json, subprocess, sys
PKG = "com.zhiliaoapp.musically"
OUT = r"e:\tiktok_signer\re\out\msb_mod7632.json"
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 26
JS = r"""
Java.perform(function(){
 try{
  var MS=Java.use("com.bytedance.mobsec.metasec.ov.MS");
  var ov=MS.b.overloads; send("MS.b overloads="+ov.length);
  var want={'10003':1,'1000011':1,'1000010':1,'1000022':1,'1000023':1,'30001':1,'10001':1,'10002':1,'1000000b':1};
  ov.forEach(function(m){
    m.implementation=function(){
      var a=arguments; var cmd=(a[0]>>>0); var ret;
      try{ ret=m.apply(this,a); }catch(e){ ret=null; }
      var ch=cmd.toString(16);
      if(want[ch]){
        var s=(a.length>3&&a[3]!=null)?(""+a[3]):"";
        var o=(a.length>4&&a[4]!=null)?(""+a[4]):"";
        var r=(ret===null||ret===undefined)?"null":(""+ret);
        send(JSON.stringify({cmd:ch,s:s.slice(0,140),o:o.slice(0,140),r:r.slice(0,220)}));
      }
      return ret;
    };
  });
  send("hooked-MS.b");
 }catch(e){ send("ERR "+e); }
});
"""
col = []
def onmsg(m, d):
    if m.get("type") == "send":
        p = m["payload"]
        if p.startswith("{"):
            try: col.append(json.loads(p))
            except Exception: col.append({"raw": p})
        else:
            print("[meta]", p, flush=True)
    elif m.get("type") == "error":
        print("[jserr]", (m.get("stack","") or "")[:200], flush=True)

def sh(c): subprocess.run(["adb","shell",c], capture_output=True)

dev = frida.get_usb_device(timeout=10)
sh("am force-stop " + PKG)
time.sleep(1)
sh("monkey -p " + PKG + " -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1")
pid = None
for i in range(30):
    try:
        pid = dev.get_process(PKG).pid; break
    except Exception:
        time.sleep(1)
if not pid:
    print("[!] process not up after launch (mod crash / anti-frida?)", flush=True); sys.exit(2)
print("[*] pid", pid, "— attach", flush=True)
time.sleep(4)  # JVM/init settle
sess = dev.attach(pid)
sc = sess.create_script(JS); sc.on("message", onmsg); sc.load()
print("[*] hooked, collecting %ds + swipe feed" % DUR, flush=True)
# trigger signing traffic
for k in range(0, DUR, 6):
    sh("input swipe 360 1200 360 450 300")
    time.sleep(3)
    sh("input swipe 360 450 360 1200 300")
    time.sleep(3)
try: sess.detach()
except Exception: pass
json.dump(col, open(OUT, "w"), ensure_ascii=False, indent=1)
print("[*] saved %d events -> %s" % (len(col), OUT), flush=True)
# quick tally
from collections import Counter
c = Counter(e.get("cmd") for e in col)
print("[*] per-cmd:", dict(c), flush=True)
gets = [e for e in col if e.get("cmd") == "1000022" and e.get("r") not in (None, "null", "")]
print("[*] keva GET non-null sample:", len(gets), flush=True)
for e in gets[:25]:
    print("   GET entry=%s val=%s" % (e.get("o"), e.get("r")), flush=True)

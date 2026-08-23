#!/usr/bin/env python3
# E-seed/E-PI recon v2: ATTACH app dang chay (JVM ready -> Java defined; tranh spawn pre-JVM).
# Capture plaintext MS.b: keva GET 0x1000022 (ret=value), SET 0x1000023 (k+v), 0x30001 network, signals.
# 2 mode ONLINE vs OFFLINE -> cai nao xuat hien offline = self-derived.
import frida, subprocess, time, os, json
from collections import Counter
PKG = "com.zhiliaoapp.musically"
OUT = "e:/tiktok_signer/re/out"; os.makedirs(OUT, exist_ok=True)
def sh(c): subprocess.run(["adb","shell",c], capture_output=True)
def rev(): subprocess.run(["adb","reverse","tcp:8082","tcp:8082"], capture_output=True)

JS = r"""
Java.perform(function(){
 try{
  var MS=Java.use("com.bytedance.mobsec.metasec.ov.MS");
  var ov=MS.b.overloads; var total=0;
  send("HB hooked MS.b overloads="+ov.length);
  var want={0x10003:1,0x1000011:1,0x1000010:1,0x1000022:1,0x1000023:1,0x30001:1,0x10001:1,0x10002:1,0x2000001:1,0x1000000b:1};
  function cap(x,n){ try{ var s=(x===null||x===undefined)?"null":(""+x); return s.length>n? s.substring(0,n)+"...": s; }catch(e){ return "?"; } }
  ov.forEach(function(m){
    m.implementation=function(){
      var a=arguments; total++;
      var cmd=(a[0]>>>0);
      var ret; try{ ret=m.apply(this,a); }catch(e){ ret=null; }
      if(want[cmd]){
        try{
          var s=cap(a.length>3?a[3]:null,90);
          var o="";
          if(cmd===0x30001){ try{ var b=(a[4]&&a[4].length>0)?a[4][0]:null; o="bodylen="+(b?b.length:-1); }catch(e){ o="o?"; } }
          else { o=cap(a.length>4?a[4]:null,90); }
          var r;
          if(cmd===0x30001){ var st="?",rl=-1; try{st=cap(ret[0],20);}catch(e){} try{rl=ret[1]?ret[1].length:-1;}catch(e){} r="status="+st+" resplen="+rl; }
          else { r=cap(ret,300); }
          send(JSON.stringify({cmd:cmd,s:s,o:o,ret:r}));
        }catch(e){ send("LOGERR 0x"+cmd.toString(16)+" "+e); }
      }
      return ret;
    };
  });
  setInterval(function(){ send("HB total="+total); }, 8000);
 }catch(e){ send("ERR "+e); }
});
"""

def run_mode(mode, dur=38):
    if mode == "offline":
        sh("settings put global http_proxy :0"); sh("svc wifi disable"); sh("svc data disable")
    else:
        sh("settings put global http_proxy 127.0.0.1:8082"); rev(); sh("svc wifi enable"); sh("svc data enable")
    # app running + foreground
    sh("monkey -p %s -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1" % PKG)
    time.sleep(4)  # JVM ready + metasec init
    coll = []; hb = []
    def onmsg(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.startswith("HB "): hb.append(p); print("  [HB]", p, flush=True)
            else:
                try: ev = json.loads(p)
                except Exception: ev = {"raw": p}
                coll.append(ev); print("  [ev] 0x%x s=%r o=%r ret=%r" % (ev.get("cmd",0), ev.get("s"), ev.get("o"), ev.get("ret")), flush=True)
        elif m.get("type") == "error":
            print("  [JSERR]", (m.get("stack","") or "")[:240], flush=True)
    dev = frida.get_usb_device(timeout=10)
    try:
        s = dev.attach(PKG); print(f"[{mode}] attached running {PKG}", flush=True)
    except Exception as e:
        print(f"[{mode}] ATTACH FAIL: {e}", flush=True); return coll
    sc = s.create_script(JS); sc.on("message", onmsg); sc.load()
    # trigger foreground fetch sau khi hook bam
    sh("monkey -p %s -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1" % PKG)
    print(f"[{mode}] running {dur}s ...", flush=True)
    time.sleep(dur)
    try: s.detach()
    except Exception: pass
    json.dump(coll, open(os.path.join(OUT, f"msb_{mode}.json"), "w"), ensure_ascii=False, indent=1)
    c = Counter(e.get("cmd") for e in coll)
    print(f"[{mode}] DONE events={len(coll)} lastHB={hb[-1] if hb else 'NONE'} per_cmd=" +
          ", ".join(f"0x{k:x}:{v}" for k, v in sorted(c.items())), flush=True)
    sets = [e for e in coll if e.get("cmd") == 0x1000023]
    gets = [e for e in coll if e.get("cmd") == 0x1000022]
    net  = [e for e in coll if e.get("cmd") == 0x30001]
    print(f"[{mode}] keva GET={len(gets)} SET={len(sets)} NET={len(net)}", flush=True)
    seen = {}
    for e in gets:
        k = e.get('s'); seen[k] = e.get('ret')
    for k, v in seen.items(): print(f"   KEVA-GET key={k} val={v}", flush=True)
    for e in sets: print(f"   KEVA-SET key={e.get('s')} val={e.get('o')}", flush=True)
    for e in net:  print(f"   NET url={str(e.get('s'))[:55]} {e.get('ret')}", flush=True)
    return coll

print("############ MODE=online ############", flush=True); run_mode("online", 38)
print("############ MODE=offline ############", flush=True); run_mode("offline", 38)
sh("svc wifi enable"); sh("settings put global http_proxy 127.0.0.1:8082")
print("############ ALL DONE (wifi+proxy restored) ############", flush=True)

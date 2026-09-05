import frida, sys, time, json, os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 80
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","init_dump_ce0516.json")
JS=r"""
function rd(p){try{if(p.isNull())return null;var s=p.readCString();return (s&&/[ -~]/.test(s))?s:null;}catch(e){return null;}}
function deepUrl(a,i){ // arg direct, or *(arg), or *(arg+off)
  var d=rd(a[i]); if(d&&d.indexOf("http")===0)return {w:"a"+i,s:d};
  for(var off=0;off<0x30;off+=8){try{var pp=a[i].add(off).readPointer();var s=rd(pp);if(s&&s.indexOf("http")===0)return{w:"a"+i+"+"+off,s:s};}catch(e){}}
  return null;
}
var done=false;
var iv=setInterval(function(){
  if(done)return;var m=Process.findModuleByName("libsscronet.so");if(!m)return;
  var init=m.findExportByName("Cronet_UrlRequest_InitWithParams");if(!init)return;
  done=true;clearInterval(iv);
  Interceptor.attach(init,{onEnter:function(a){try{
    var found=null;
    for(var i=0;i<7;i++){var r=deepUrl(a,i);if(r){found=r;break;}}
    if(found){
      var seed=/get_seed|\/ms\/|mssdk/i.test(found.s);
      send({tag:seed?"SEED":"URL",where:found.w,url:found.s});
    }
  }catch(e){}}});
  send({tag:"info",msg:"hooked InitWithParams @"+init});
},100);
"""
seed=[];urls=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="SEED":print("\n[+++ SEED URL]",p["where"],p["url"],flush=True);seed.append(p)
        elif t=="URL":urls.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",on_message);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump({"seed":seed,"urls":urls},open(OUT,"w"),indent=1)
print(f"\n=== {len(seed)} SEED / {len(urls)} url-bearing calls; where-histogram:",flush=True)
from collections import Counter
print("  where:",dict(Counter(u["where"] for u in urls)),flush=True)
import re
print("  hosts:",dict(Counter(re.sub(r"(https?://[^/]+).*",r"\1",u["url"]) for u in urls).most_common(15)),flush=True)

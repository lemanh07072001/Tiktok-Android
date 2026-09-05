import frida, sys, time, json, os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 90
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","cronet_seed_ce0516.json")
JS=r"""
function tryStr(p){try{if(p.isNull())return null;var s=p.readCString();return (s&&s.length)?s:null;}catch(e){return null;}}
function scanArgForUrl(a,idx){ // arg may be ptr-to-string or ptr-to-struct containing string ptr
  for(var off=0; off<0x40; off+=8){
    try{var pp=a[idx].add(off).readPointer();var s=tryStr(pp);
      if(s && s.indexOf("http")===0) return {via:"deref+"+off, s:s};}catch(e){}
  }
  var d=tryStr(a[idx]); if(d && d.indexOf("http")===0) return {via:"direct", s:d};
  return null;
}
var done=false;
var iv=setInterval(function(){
  if(done)return;var m=Process.findModuleByName("libsscronet.so");if(!m)return;
  var init=m.findExportByName("Cronet_UrlRequest_InitWithParams");if(!init)return;
  done=true;clearInterval(iv);
  Interceptor.attach(init,{onEnter:function(a){try{
    var found=null;
    for(var i=1;i<=5;i++){var r=scanArgForUrl(a,i);if(r){found={arg:i,via:r.via,url:r.s};break;}}
    if(!found)return;
    var seed=/get_seed|\/ms\/|mssdk/i.test(found.url);
    send({tag: seed?"SEED":"URL", arg:found.arg, via:found.via, url:found.url});
  }catch(e){}}});
  send({tag:"info",msg:"HOOKED init @"+init});
},120);
"""
seed=[];urls=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="SEED":print("[+SEED]",f"arg{p['arg']}/{p['via']}",p["url"][:200],flush=True);seed.append(p)
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
print(f"\n=== {len(seed)} SEED urls / {len(urls)} total urls ===",flush=True)
import re
from collections import Counter
c=Counter(re.sub(r"(https?://[^/]+).*",r"\1",u["url"]) for u in urls if u.get("url"))
for h,n in c.most_common(25):print(f"  {n:3d} {h[:70]}",flush=True)
via=Counter(u["via"] for u in urls)
print("via:",dict(via),"| first url sample:",urls[0]["url"][:120] if urls else "-",flush=True)

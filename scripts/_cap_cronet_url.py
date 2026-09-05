import frida, sys, time, json, os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 90
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","cronet_urls_ce0516.json")
JS=r"""
function cstr(p){try{return p.isNull()?"":p.readUtf8String();}catch(e){return "?";}}
var done=false;
var iv=setInterval(function(){
  if(done)return;
  var m=Process.findModuleByName("libsscronet.so");
  if(!m)return;
  var init=m.findExportByName("Cronet_UrlRequest_InitWithParams");
  if(!init)return;
  done=true;clearInterval(iv);
  Interceptor.attach(init,{onEnter:function(a){try{
    var url=cstr(a[2]);
    if(!url)return;
    var gs=url.indexOf("get_seed")>=0 || url.indexOf("/ms/")>=0;
    send({tag: gs?"SEED":"URL", url:url});
  }catch(e){}}});
  send({tag:"info",msg:"HOOKED Cronet_UrlRequest_InitWithParams @"+init});
},120);
setTimeout(function(){if(!done)send({tag:"info",msg:"init export NOT found after 20s"});},20000);
"""
seed=[];urls=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="SEED":print("[+SEED URL]",p["url"],flush=True);seed.append(p["url"])
        elif t=="URL":urls.append(p["url"])
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",on_message);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump({"seed_urls":seed,"all_urls":urls},open(OUT,"w"),indent=1)
print(f"\n=== {len(seed)} seed URLs, {len(urls)} other URLs ===",flush=True)
from collections import Counter
import re
hosts=Counter(re.sub(r"https?://([^/]+).*",r"\1",u) for u in urls)
for h,c in hosts.most_common(20):print(f"  {c:3d} {h[:60]}")
print("SEED URLS:",flush=True)
for u in seed[:10]:print("  ",u,flush=True)

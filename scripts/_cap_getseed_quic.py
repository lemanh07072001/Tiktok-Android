import frida, sys, time, json, os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 90
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","getseed_quic_ce0516.json")
JS=r"""
function readable(p){try{if(p.isNull())return false;p.readU8();return true;}catch(e){return false;}}
var done=false;
var iv=setInterval(function(){
  if(done)return;
  var m=Process.findModuleByName("libsscronet.so");
  if(!m)return;
  function ex(n){return m.findExportByName(n);}
  var e_urlget=ex("Cronet_UrlResponseInfo_url_get");
  var e_status=ex("Cronet_UrlResponseInfo_http_status_code_get");
  var e_bufdata=ex("Cronet_Buffer_GetData");
  var e_bufsize=ex("Cronet_Buffer_GetSize");
  if(!e_urlget||!e_bufdata){return;}
  done=true;clearInterval(iv);
  var url_get=new NativeFunction(e_urlget,"pointer",["pointer"]);
  var status_get=e_status?new NativeFunction(e_status,"int",["pointer"]):null;
  var buf_data=new NativeFunction(e_bufdata,"pointer",["pointer"]);
  var buf_size=e_bufsize?new NativeFunction(e_bufsize,"uint64",["pointer"]):null;
  function urlOf(info){try{if(!readable(info))return null;var p=url_get(info);if(p.isNull())return null;return p.readCString();}catch(e){return null;}}
  function hx(p,n){try{var b=new Uint8Array(p.readByteArray(Math.min(n,4096)));var h="";for(var i=0;i<b.length;i++)h+=("0"+b[i].toString(16)).slice(-2);return h;}catch(e){return "";}}
  // distinct callback addresses (some ICF-folded)
  var names=["Cronet_UrlRequestCallback_OnResponseStarted","Cronet_UrlRequestCallback_OnReadCompleted",
             "TTQuicHe_HttpRequestCallback_OnResponseStarted","TTQuicHe_HttpRequestCallback_OnReadCompleted",
             "Cronet_UrlRequestCallback_OnSucceeded","TTQuicHe_HttpRequestCallback_OnSucceeded"];
  var seenAddr={};var seenUrl={};
  names.forEach(function(nm){
    var a=ex(nm);if(!a)return;var key=a.toString();if(seenAddr[key])return;seenAddr[key]=1;
    Interceptor.attach(a,{onEnter:function(ar){try{
      var info=ar[2];var url=urlOf(info);
      if(!url)return;
      var isSeed=/get_seed|\/ms\//i.test(url);
      if(!isSeed){var host=url.split("/").slice(0,3).join("/");if(!seenUrl[host]){seenUrl[host]=1;send({tag:"host",url:host});}return;}
      var st=status_get?(function(){try{return status_get(info);}catch(e){return -1;}})():-1;
      // arg3=buffer, arg4=bytesRead (uint64) — may be garbage if this variant has no body
      var n=0;try{n=ar[4].toInt32();}catch(e){}
      var body="";
      if(n>0&&n<200000){try{var bp=buf_data(ar[3]);if(readable(bp))body=hx(bp,n);}catch(e){}}
      send({tag:"SEED",fn:nm,url:url,status:st,n:n,body:body});
    }catch(e){}}});
  });
  send({tag:"info",msg:"hooked "+Object.keys(seenAddr).length+" cb addrs; url_get@"+e_urlget});
},100);
setTimeout(function(){if(!done)send({tag:"info",msg:"libsscronet exports not ready 25s"});},25000);
"""
seed=[];hosts=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="host":hosts.append(p["url"])
        elif t=="SEED":
            print(f"\n[+++ SEED CALLBACK] fn={p['fn']}\n   url={p['url']}\n   status={p['status']} n={p['n']}\n   body[:96]={p['body'][:96]}",flush=True)
            seed.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (get_seed QUIC cb capture)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",on_message);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump({"seed":seed,"hosts":sorted(set(hosts))},open(OUT,"w"),indent=1)
print(f"\n=== {len(seed)} SEED callbacks | {len(set(hosts))} distinct hosts seen ===",flush=True)
for h in sorted(set(hosts))[:25]:print("  ",h,flush=True)

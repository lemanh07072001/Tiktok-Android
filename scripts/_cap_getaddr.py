import frida, sys, time, json, os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 90
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","getseed_diag_ce0516.json")
JS=r"""
var seen={};
// 1) getaddrinfo: arg0 = hostname (transport-agnostic DNS)
var lc=Process.findModuleByName("libc.so");var gai=lc?lc.findExportByName("getaddrinfo"):null;
if(gai) Interceptor.attach(gai,{onEnter:function(a){try{
  var h=a[0].isNull()?"":a[0].readCString();
  if(h && !seen["dns:"+h]){seen["dns:"+h]=1;
    var seed=/mssdk|get_seed|\/ms\//i.test(h);
    send({tag: seed?"SEED_DNS":"DNS", host:h});}
}catch(e){}}});
// 2) SSL_write on libttboringssl (TLS payload for TCP)
function asc(p,n){var b=new Uint8Array(p.readByteArray(Math.min(n,300)));var s="";for(var i=0;i<b.length;i++){var c=b[i];s+=(c>=32&&c<127)?String.fromCharCode(c):".";}return s;}
var done=false;
var iv=setInterval(function(){
  if(done)return;var m=Process.findModuleByName("libttboringssl.so");if(!m)return;
  var W=m.findExportByName("SSL_write");if(!W)return;done=true;clearInterval(iv);
  Interceptor.attach(W,{onEnter:function(a){try{
    var n=a[2].toInt32();if(n<=0||n>200000)return;var head=asc(a[1],n);
    var hm=head.match(/[Hh]ost: ([^\r\n]+)/);var rl=head.match(/^(GET|POST|PUT) ([^ ]+)/);
    if(head.indexOf("get_seed")>=0||head.indexOf("/ms/")>=0){send({tag:"SEED_TLS",head:head});}
    else if(rl){var h=hm?hm[1]:"?";if(!seen["tls:"+h+rl[2].slice(0,30)]){seen["tls:"+h+rl[2].slice(0,30)]=1;send({tag:"TLS",host:h,line:rl[1]+" "+rl[2].slice(0,40)});}}
  }catch(e){}}});
  send({tag:"info",msg:"SSL_write hooked"});
},120);
"""
ev=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="SEED_DNS":print("[+SEED DNS]",p["host"],flush=True);ev.append(p)
        elif t=="SEED_TLS":print("[+SEED TLS]\n",p["head"][:400],flush=True);ev.append(p)
        elif t=="DNS":print("[dns]",p["host"],flush=True);ev.append(p)
        elif t=="TLS":print("[tls]",p["host"],p["line"],flush=True);ev.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",on_message);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump(ev,open(OUT,"w"),indent=1)
seeds=[e for e in ev if "SEED" in e["tag"]]
print(f"\n=== {len(ev)} events, {len(seeds)} SEED-related ===",flush=True)

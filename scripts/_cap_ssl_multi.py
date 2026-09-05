import frida, sys, time, json, os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 90
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","getseed_sslmulti_ce0516.json")
JS=r"""
function asc(p,n){try{var b=new Uint8Array(p.readByteArray(Math.min(n,400)));var s="";for(var i=0;i<b.length;i++){var c=b[i];s+=(c>=32&&c<127)?String.fromCharCode(c):".";}return s;}catch(e){return"";}}
function hx(p,n){try{var b=new Uint8Array(p.readByteArray(Math.min(n,2048)));var h="";for(var i=0;i<b.length;i++)h+=("0"+b[i].toString(16)).slice(-2);return h;}catch(e){return"";}}
var armed={};
function hookLib(nm){
  var m=Process.findModuleByName(nm);if(!m)return false;
  var W=m.findExportByName("SSL_write"),R=m.findExportByName("SSL_read");
  if(!W||!R)return false;
  Interceptor.attach(W,{onEnter:function(a){try{
    var n=a[2].toInt32();if(n<=0||n>300000)return;var head=asc(a[1],n);
    var rl=head.match(/^(GET|POST|PUT) ([^ ]+) HTTP/);var hm=head.match(/[Hh]ost: ([^\r\n]+)/);
    if(head.indexOf("get_seed")>=0||head.indexOf("/ms/")>=0){
      send({tag:"SEED_REQ",lib:nm,host:hm?hm[1]:"?",head:head,hex:hx(a[1],n),len:n});
      armed[a[0].toString()]=6;
    } else if(rl){send({tag:"host",lib:nm,host:(hm?hm[1]:"?")+" "+rl[2].slice(0,40)});}
  }catch(e){}}});
  Interceptor.attach(R,{onEnter:function(a){this.s=a[0];this.b=a[1];},onLeave:function(ret){try{
    var k=this.s.toString();if(!(k in armed))return;var n=ret.toInt32();if(n<=0)return;
    send({tag:"SEED_RESP",lib:nm,len:n,hex:hx(this.b,n)});armed[k]-=1;if(armed[k]<=0)delete armed[k];
  }catch(e){}}});
  send({tag:"info",msg:"hooked SSL on "+nm});return true;
}
var libs=["libttboringssl.so","libssl.so","libttcrypto.so","libpns_crypto.so"];
var got={};
var iv=setInterval(function(){
  libs.forEach(function(l){if(!got[l]&&hookLib(l))got[l]=1;});
},150);
setTimeout(function(){clearInterval(iv);send({tag:"info",msg:"stop polling; hooked="+Object.keys(got).join(",")});},20000);
"""
ev=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="host":ev.append(p)
        elif t=="SEED_REQ":print(f"\n[+++ SEED REQ] lib={p['lib']} host={p['host']} len={p['len']}\n{p['head'][:500]}",flush=True);ev.append(p)
        elif t=="SEED_RESP":print(f"[+++ SEED RESP] lib={p['lib']} len={p['len']} hex={p['hex'][:80]}",flush=True);ev.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s multi-SSL",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",on_message);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump(ev,open(OUT,"w"),indent=1)
sq=[e for e in ev if e["tag"].startswith("SEED")]
hh=sorted(set(e["host"] for e in ev if e["tag"]=="host"))
print(f"\n=== {len(sq)} SEED events | {len(hh)} hosts ===",flush=True)
for h in hh[:30]:print("   ",h,flush=True)

#!/usr/bin/env python3
import frida, time, sys, os, json
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 70
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","getseed_ce0516_live.json")
JS=r"""
var armed={};
function hexOf(p,n){var b=new Uint8Array(p.readByteArray(n));var h="";for(var i=0;i<n;i++)h+=("0"+b[i].toString(16)).slice(-2);return h;}
function asc(p,n){var b=new Uint8Array(p.readByteArray(Math.min(n,400)));var s="";for(var i=0;i<b.length;i++){var c=b[i];s+=(c>=32&&c<127)?String.fromCharCode(c):".";}return s;}
function installOn(mm){
  var W=mm.findExportByName("SSL_write"), R=mm.findExportByName("SSL_read");
  if(!W||!R) return false;
  Interceptor.attach(W,{onEnter:function(a){try{
    this.ssl=a[0];var num=a[2].toInt32();if(num<=0||num>200000)return;
    var head=asc(a[1],num);
    var m=head.match(/^(GET|POST|PUT) ([^ ]+) HTTP/);
    var hm=head.match(/[Hh]ost: ([^\r\n]+)/);
    if(head.indexOf("get_seed")>=0){send({tag:"REQ",ssl:this.ssl.toString(),len:num,ascii:head,hex:hexOf(a[1],num)});armed[this.ssl.toString()]=8;}
    else if(m)send({tag:"HTTP",host:hm?hm[1]:"?",line:m[1]+" "+m[2].slice(0,50)});
  }catch(e){}}});
  Interceptor.attach(R,{onEnter:function(a){this.ssl=a[0];this.buf=a[1];},onLeave:function(ret){try{
    var k=this.ssl.toString();if(!(k in armed))return;var n=ret.toInt32();if(n<=0)return;
    send({tag:"RESP",ssl:k,len:n,hex:hexOf(this.buf,n)});armed[k]-=1;if(armed[k]<=0)delete armed[k];
  }catch(e){}}});
  return true;
}
var done=false;
var iv=setInterval(function(){
  if(done)return;
  var mm=Process.findModuleByName("libttboringssl.so");
  if(mm && installOn(mm)){done=true;clearInterval(iv);send({tag:"info",msg:"HOOKED libttboringssl.so"});}
},150);
setTimeout(function(){if(!done){var mm=Process.findModuleByName("libssl.so");if(mm&&installOn(mm))send({tag:"info",msg:"fallback HOOKED libssl.so"});}},15000);
"""
events=[];hosts={}
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p.get("tag")
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="REQ":print(f"[+] REQ len={p['len']} ascii={p['ascii'][:120]!r}",flush=True);events.append(p)
        elif t=="RESP":print(f"[+] RESP len={p['len']} hex={p['hex'][:48]}",flush=True);events.append(p)
        elif t=="HTTP":hosts[p['host']]=hosts.get(p['host'],0)+1
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
def main():
    dev=frida.get_usb_device(timeout=10)
    print(f"[*] spawn {PKG}, capture {DUR}s",flush=True)
    pid=dev.spawn([PKG]);s=dev.attach(pid)
    st={"mine":False,"dead":False}
    def det(reason,*a):
        if not st["mine"]:st["dead"]=True;print("[!!] APP REALLY DIED:",reason,flush=True)
    s.on("detached",det)
    sc=s.create_script(JS);sc.on("message",on_message);sc.load();dev.resume(pid)
    t0=time.time()
    while time.time()-t0<DUR and not st["dead"]:time.sleep(0.5)
    st["mine"]=True
    try:s.detach()
    except:pass
    with open(OUT,"w") as f:json.dump(events,f,indent=1)
    print("\n=== HOSTS (top 20) ===",flush=True)
    for h,c in sorted(hosts.items(),key=lambda x:-x[1])[:20]:print(f"   {c:4d}  {h[:70]}")
    reqs=[e for e in events if e['tag']=='REQ'];resps=[e for e in events if e['tag']=='RESP']
    print(f"\n[*] get_seed: {len(reqs)} REQ / {len(resps)} RESP -> {OUT}",flush=True)
if __name__=="__main__":main()

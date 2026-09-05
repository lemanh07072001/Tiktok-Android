import frida,sys,time
PKG="com.zhiliaoapp.musically"
JS=r"""
var m=null;
var iv=setInterval(function(){
  m=Process.findModuleByName("libmetasec_ov.so");
  if(m){clearInterval(iv);go();}
},150);
function go(){
  var imps=m.enumerateImports();
  var net=[];var all=[];
  imps.forEach(function(e){
    var n=e.name;var l=n.toLowerCase();
    all.push(n);
    if(l.indexOf("socket")>=0||l.indexOf("send")>=0||l.indexOf("recv")>=0||l.indexOf("connect")>=0||
       l.indexOf("ssl")>=0||l.indexOf("cronet")>=0||l.indexOf("quic")>=0||l.indexOf("curl")>=0||
       l.indexOf("http")>=0||l.indexOf("getaddr")>=0||l.indexOf("dns")>=0||l.indexOf("write")>=0||
       l.indexOf("read")>=0||l.indexOf("tls")>=0||l.indexOf("evp_")>=0||l.indexOf("aead")>=0){
      net.push((e.module||"?")+" :: "+n);
    }
  });
  send({tag:"imp",total:imps.length,net:net});
  // also: which OTHER modules does it depend on? list distinct import modules
  var mods={};imps.forEach(function(e){if(e.module)mods[e.module]=(mods[e.module]||0)+1;});
  send({tag:"mods",mods:mods});
}
setTimeout(function(){send({tag:"end"});},9000);
"""
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="imp":
            print(f"\n== libmetasec_ov imports total={p['total']} | network-ish: {len(p['net'])} ==",flush=True)
            for h in p["net"]:print("   ",h,flush=True)
        elif t=="mods":
            print("\n== import source modules ==",flush=True)
            for k,v in sorted(p["mods"].items(),key=lambda x:-x[1]):print(f"   {v:4d}  {k}",flush=True)
        elif t=="end":print("\n[end]",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(11)
try:s.detach()
except:pass

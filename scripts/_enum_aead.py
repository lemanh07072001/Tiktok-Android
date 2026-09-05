import frida,sys,time
PKG="com.zhiliaoapp.musically"
JS=r"""
var libs=["libttboringssl.so","libsscronet.so","libssl.so","libcrypto.so","libmetasec_ov.so"];
function scan(nm){
  var m=Process.findModuleByName(nm);if(!m){return;}
  var ex=m.enumerateExports();var hits=[];
  ex.forEach(function(e){
    var n=e.name.toLowerCase();
    if(n.indexOf("aead")>=0||n.indexOf("evp_aead")>=0||(n.indexOf("quic")>=0&&(n.indexOf("crypt")>=0||n.indexOf("seal")>=0||n.indexOf("open")>=0||n.indexOf("aead")>=0))||n=="evp_aead_ctx_open"||n=="evp_aead_ctx_seal"){
      hits.push(e.name+" @"+e.address);
    }
  });
  send({tag:"lib",nm:nm,total:ex.length,hits:hits.slice(0,40)});
}
var done={};
var iv=setInterval(function(){libs.forEach(function(l){if(!done[l]&&Process.findModuleByName(l)){done[l]=1;scan(l);}});},150);
setTimeout(function(){clearInterval(iv);send({tag:"end"});},9000);
"""
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p["tag"]=="lib":
            print(f"\n== {p['nm']} (exports={p['total']}) ==",flush=True)
            for h in p["hits"]:print("   ",h,flush=True)
            if not p["hits"]:print("    (no aead/quic-crypto exports)",flush=True)
        elif p["tag"]=="end":print("\n[end]",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(11)
try:s.detach()
except:pass

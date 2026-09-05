import frida,sys,time
PKG="com.zhiliaoapp.musically"
JS=r"""
var libs=["libsscronet.so","libttboringssl.so"];
function scan(nm){
  var m=Process.findModuleByName(nm);if(!m)return;
  var syms;try{syms=m.enumerateSymbols();}catch(e){send({tag:"err",nm:nm,e:''+e});return;}
  var hits=[];
  syms.forEach(function(s){
    var n=s.name;var l=n.toLowerCase();
    if(l.indexOf("aead")>=0||l.indexOf("evp_aead")>=0||l==="evp_aead_ctx_seal"||l==="evp_aead_ctx_open"||
       (l.indexOf("gcm")>=0&&l.indexOf("crypt")>=0)||l.indexOf("quic_crypt")>=0||l.indexOf("ahead")>=0){
      hits.push((s.type||"?")+" "+n+" @"+s.address);
    }
  });
  send({tag:"lib",nm:nm,total:syms.length,hits:hits.slice(0,60)});
}
var done={};
var iv=setInterval(function(){libs.forEach(function(l){if(!done[l]&&Process.findModuleByName(l)){done[l]=1;scan(l);}});},150);
setTimeout(function(){clearInterval(iv);send({tag:"end"});},9000);
"""
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="lib":
            print(f"\n== {p['nm']} (symbols={p['total']}) ==",flush=True)
            for h in p["hits"]:print("   ",h,flush=True)
            if not p["hits"]:print("    (no aead/gcm local symbols — stripped)",flush=True)
        elif t=="err":print(f"[err {p['nm']}] {p['e']}",flush=True)
        elif t=="end":print("\n[end]",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
time.sleep(11)
try:s.detach()
except:pass

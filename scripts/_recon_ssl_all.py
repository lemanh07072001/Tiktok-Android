import frida, sys, time, os
PKG="com.zhiliaoapp.musically"
JS=r"""
var mods=Process.enumerateModules();
var hits=[];
mods.forEach(function(m){
  try{
    var w=Module.findExportByName(m.name,"SSL_write");
    var r=Module.findExportByName(m.name,"SSL_read");
    if(w||r) hits.push(m.name+"  W="+(w?w:"-")+"  R="+(r?r:"-"));
  }catch(e){}
});
send({tag:"info",msg:"SSL export modules ("+hits.length+"):\n"+hits.join("\n")});
var netmods=mods.filter(function(m){return /ssl|crypto|cronet|boring|metasec|sscronet|ttnet|quic|npth|sec/i.test(m.name);})
  .map(function(m){return m.name+" sz="+m.size;});
send({tag:"info",msg:"net-ish modules ("+netmods.length+"):\n"+netmods.join("\n")});
["get_seed","mssdk22-normal","/ms/get_seed"].forEach(function(pat){
  try{
    var found=[];
    var hx=pat.split("").map(function(c){return ("0"+c.charCodeAt(0).toString(16)).slice(-2);}).join(" ");
    Process.enumerateRanges("r--").forEach(function(rg){
      if(found.length>4)return;
      try{Memory.scanSync(rg.base,rg.size,hx).forEach(function(x){
        if(found.length>4)return;
        var mo=Process.findModuleByAddress(x.address);
        found.push(""+x.address+" in "+(mo?mo.name:"anon"));
      });}catch(e){}
    });
    send({tag:"info",msg:"scan '"+pat+"' -> "+(found.length?found.join(" | "):"none")});
  }catch(e){send({tag:"info",msg:"scan '"+pat+"' err "+e});}
});
"""
def on_message(m,d):
    if m.get("type")=="send":print(m["payload"].get("msg",m["payload"]),flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
pid=int(sys.argv[1])
print("[*] attach pid",pid,flush=True)
s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",on_message);sc.load()
time.sleep(9)
s.detach()

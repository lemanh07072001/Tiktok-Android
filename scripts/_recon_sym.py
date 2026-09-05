import frida, sys, time
JS=r"""
["libttboringssl.so","libsscronet.so","libttcrypto.so","libssl.so"].forEach(function(nm){
  var m=Process.findModuleByName(nm);
  if(!m){send({tag:"info",msg:nm+" NOT LOADED"});return;}
  var syms=[];
  try{
    m.enumerateSymbols().forEach(function(s){
      if(/^SSL_(write|read|do_handshake|connect)$/.test(s.name)) syms.push(s.name+" @"+s.address+" ("+s.type+")");
    });
  }catch(e){syms.push("symerr "+e);}
  var exps=[];
  try{
    m.enumerateExports().forEach(function(s){
      if(/SSL_write|SSL_read|Cronet_UrlRequest_InitWithParams|Cronet_UrlRequest/.test(s.name)) exps.push(s.name+" @"+s.address);
    });
  }catch(e){exps.push("experr "+e);}
  send({tag:"info",msg:"["+nm+"] size="+m.size+"\n  SSL syms: "+(syms.length?syms.join(", "):"none")+"\n  interesting exports: "+(exps.length?exps.slice(0,10).join(", "):"none")});
});
// count total exports of libsscronet + sample Cronet_ names
var sc=Process.findModuleByName("libsscronet.so");
if(sc){
  var cn=[];
  sc.enumerateExports().forEach(function(s){if(/Cronet_/.test(s.name)&&cn.length<25)cn.push(s.name);});
  send({tag:"info",msg:"libsscronet Cronet_ exports sample ("+cn.length+"):\n"+cn.join("\n")});
}
"""
def on_message(m,d):
    if m.get("type")=="send":print(m["payload"].get("msg",m["payload"]),flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
s=dev.attach(int(sys.argv[1]))
sc=s.create_script(JS);sc.on("message",on_message);sc.load()
time.sleep(6); s.detach()

#!/usr/bin/env python3
import frida,sys,time
PKG="com.zhiliaoapp.musically"
JS=r"""
setTimeout(function(){
  var mods=Process.enumerateModules();
  var interesting=[];
  mods.forEach(function(m){
    if(/cronet|boring|ssl|ttnet|metasec|quic|net/i.test(m.name)) interesting.push(m.name+" @"+m.base+" sz="+m.size);
  });
  send({tag:"MODS",list:interesting});
  // tim export SSL_write/SSL_read o moi module (ke ca non-libssl)
  var hits=[];
  ["libsscronet.so","libcronet.so","libttboringssl.so","libboringssl.so","libssl.so"].forEach(function(nm){
    var mm=Process.findModuleByName(nm); if(!mm)return;
    ["SSL_write","SSL_read","SSL_get_servername","BIO_write"].forEach(function(fn){
      var e=mm.findExportByName(fn); if(e)hits.push(nm+" : "+fn+" @"+e);
    });
    // scan symbols (neu con symbol table)
    try{ mm.enumerateSymbols().forEach(function(s){ if(/^SSL_(write|read)$/.test(s.name)) hits.push(nm+" [sym] "+s.name+" @"+s.address); }); }catch(e){}
  });
  send({tag:"SSLFN",list:hits});
},7000);
"""
def on_msg(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        print("\n=== "+p.get("tag","?")+" ===")
        for x in p.get("list",[]): print("  "+x)
    elif m.get("type")=="error": print("[ERR]",m.get("description"))
dev=frida.get_usb_device(timeout=10)
print("[*] spawn",PKG)
pid=dev.spawn([PKG]); s=dev.attach(pid)
died={"v":False}
def on_det(reason,*a): died["v"]=True; print("\n[!!] APP DETACHED / DIED, reason =",reason)
s.on("detached",on_det)
sc=s.create_script(JS); sc.on("message",on_msg); sc.load(); dev.resume(pid)
for _ in range(20):
    time.sleep(1)
    if died["v"]: break
print("\n[*] app alive after loop:", "NO (died)" if died["v"] else "YES")
try: s.detach()
except: pass

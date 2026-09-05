import frida,sys,time,json,os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 60
JS=r"""
function sockaddr(p){try{if(p.isNull())return"?";var fam=p.readU16();
  if(fam==2){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();return p.add(4).readU8()+"."+p.add(5).readU8()+"."+p.add(6).readU8()+"."+p.add(7).readU8()+":"+port;}
  if(fam==10){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();return "[v6]:"+port;}
  return "fam"+fam;}catch(e){return"?";}}
var mods=Process.enumerateModules();
function modOf(a){for(var i=0;i<mods.length;i++){if(a.compare(mods[i].base)>=0&&a.compare(mods[i].base.add(mods[i].size))<0)return mods[i].name;}return "?";}
var SM=Process.getModuleByName("libc.so").findExportByName("sendmsg");
var peers={};var msInBt=0,tot=0;
Interceptor.attach(SM,{onEnter:function(a){tot++;
  var peer=sockaddr(a[1].readPointer());
  var bt=Thread.backtrace(this.context,Backtracer.ACCURATE);
  var hasMS=false,frames=[];
  for(var i=0;i<bt.length&&i<12;i++){var mn=modOf(bt[i]);if(mn.indexOf("metasec")>=0)hasMS=true;frames.push(mn);}
  if(hasMS)msInBt++;
  var key=peer+(hasMS?" [MS-in-bt]":"");
  if(!peers[key]){peers[key]=0;if(hasMS)send({tag:"MSPEER",peer:peer,frames:frames.slice(0,8)});}
  peers[key]++;
}});
send({tag:"info",msg:"hooked sendmsg, modules="+mods.length});
setInterval(function(){send({tag:"stat",tot:tot,msBt:msInBt});},10000);
rpc.exports={peers:function(){return peers;}};
"""
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="stat":print(f"[stat] sendmsg total={p['tot']} MS-in-backtrace={p['msBt']}",flush=True)
        elif t=="MSPEER":print(f"[+++ MS sendmsg] peer={p['peer']}\n     frames={p['frames']}",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (sendmsg backtrace)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:
    pr=sc.exports_sync.peers() if hasattr(sc,"exports_sync") else sc.exports.peers()
    print("\n=== distinct sendmsg peers ===",flush=True)
    for k,v in sorted(pr.items(),key=lambda x:-x[1])[:30]:print(f"   {v:5d}  {k}",flush=True)
except Exception as e:print("[peers err]",e,flush=True)
try:s.detach()
except:pass

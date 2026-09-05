import frida,sys,time,json,os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 60
JS=r"""
function sockaddr(p){try{if(p.isNull())return"?";var fam=p.readU16();
  if(fam==2){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();return "IPv4 "+p.add(4).readU8()+"."+p.add(5).readU8()+"."+p.add(6).readU8()+"."+p.add(7).readU8()+":"+port;}
  if(fam==10){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();var h="";for(var i=0;i<16;i++)h+=("0"+p.add(8+i).readU8().toString(16)).slice(-2);return "IPv6 "+h+" :"+port;}
  return "fam"+fam;}catch(e){return"?";}}
var mods=Process.enumerateModules();
function modOf(a){for(var i=0;i<mods.length;i++){if(a.compare(mods[i].base)>=0&&a.compare(mods[i].base.add(mods[i].size))<0)return mods[i].name;}return "?";}
function btHasMS(ctx){var bt=Thread.backtrace(ctx,Backtracer.ACCURATE);var f=[];var ms=false;for(var i=0;i<bt.length&&i<14;i++){var mn=modOf(bt[i]);if(mn.indexOf("metasec")>=0)ms=true;f.push(mn+"@"+bt[i]);}return{ms:ms,f:f};}
var lc=Process.getModuleByName("libc.so");
var SO=lc.findExportByName("socket"),CO=lc.findExportByName("connect"),ST=lc.findExportByName("sendto"),CN=lc.findExportByName("__connect");
Interceptor.attach(SO,{onEnter:function(a){this.dom=a[0].toInt32();this.typ=a[1].toInt32();},onLeave:function(r){var b=btHasMS(this.context);if(b.ms)send({tag:"SOCKET",dom:this.dom,typ:this.typ,fd:r.toInt32(),frames:b.f.slice(0,6)});}});
Interceptor.attach(CO,{onEnter:function(a){var peer=sockaddr(a[1]);var b=btHasMS(this.context);if(b.ms)send({tag:"CONNECT",peer:peer,frames:b.f.slice(0,6)});else if(peer.indexOf(":443")>=0||peer.indexOf(":80")>=0){/*ignore non-MS*/}}});
if(ST)Interceptor.attach(ST,{onEnter:function(a){var b=btHasMS(this.context);if(b.ms){var peer=sockaddr(a[4]);send({tag:"SENDTO",peer:peer,len:a[2].toInt32(),frames:b.f.slice(0,6)});}}});
send({tag:"info",msg:"hooked socket/connect/sendto"});
setInterval(function(){send({tag:"tick"});},15000);
"""
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="tick":print("[tick]",flush=True)
        elif t=="SOCKET":print(f"[MS socket] dom={p['dom']} type={p['typ']} fd={p['fd']} (dom2=INET dom10=INET6; type1=TCP type2=UDP)\n   {p['frames']}",flush=True)
        elif t=="CONNECT":print(f"[MS CONNECT] peer={p['peer']}\n   {p['frames']}",flush=True)
        elif t=="SENDTO":print(f"[MS SENDTO] peer={p['peer']} len={p['len']}\n   {p['frames']}",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (MS socket/connect)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass

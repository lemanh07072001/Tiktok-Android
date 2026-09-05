import frida,sys,time,json,os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 70
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","getseed_wire_ce0516.json")
JS=r"""
function hx(p,n){try{var b=new Uint8Array(p.readByteArray(Math.min(n,256)));var h="";for(var i=0;i<b.length;i++)h+=("0"+b[i].toString(16)).slice(-2);return h;}catch(e){return"";}}
function sockaddr(p){try{if(p.isNull())return"?";var fam=p.readU16();
  if(fam==2){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();var ip=p.add(4).readU8()+"."+p.add(5).readU8()+"."+p.add(6).readU8()+"."+p.add(7).readU8();return ip+":"+port;}
  if(fam==10){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();var h="";for(var i=0;i<16;i++){h+=("0"+p.add(8+i).readU8().toString(16)).slice(-2);if(i%2==1&&i<15)h+=":";}return "["+h+"]:"+port;}
  return "fam"+fam;}catch(e){return"?";}}
var MS=Process.findModuleByName("libmetasec_ov.so");
var mbase=MS?MS.base:null, mend=MS?MS.base.add(MS.size):null;
function fromMS(ra){try{return mbase&&ra.compare(mbase)>=0&&ra.compare(mend)<0;}catch(e){return false;}}
function iovdump(mh){try{
  var iov=mh.add(16).readPointer();var iovlen=mh.add(24).readU64().toNumber();
  var name=mh.readPointer();var peer=sockaddr(name);
  var tot=0,first="";
  for(var i=0;i<iovlen&&i<8;i++){var base=iov.add(i*16).readPointer();var len=iov.add(i*16+8).readU64().toNumber();tot+=len;if(i==0)first=hx(base,len);}
  return {peer:peer,tot:tot,first:first};
}catch(e){return null;}}
var SM=Process.getModuleByName("libc.so").findExportByName("sendmsg");
var RM=Process.getModuleByName("libc.so").findExportByName("recvmsg");
var nS=0,nR=0,msS=0,msR=0;
Interceptor.attach(SM,{onEnter:function(a){nS++;var ms=fromMS(this.returnAddress);
  if(!ms)return;msS++;var d=iovdump(a[1]);if(d){send({tag:"SEND",peer:d.peer,len:d.tot,first:d.first});}
}});
Interceptor.attach(RM,{onEnter:function(a){this.mh=a[1];this.ms=fromMS(this.returnAddress);},onLeave:function(r){
  nR++;if(!this.ms)return;var n=r.toInt32();if(n<=0)return;msR++;var d=iovdump(this.mh);if(d){send({tag:"RECV",peer:d.peer,len:n,first:d.first});}
}});
send({tag:"info",msg:"MS="+(mbase?mbase:"null")+" sendmsg@"+SM+" recvmsg@"+RM});
setInterval(function(){send({tag:"stat",send:nS,recv:nR,msSend:msS,msRecv:msR});},10000);
"""
ev=[]
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="stat":print(f"[stat] sendmsg={p['send']}(MS {p['msSend']}) recvmsg={p['recv']}(MS {p['msRecv']})",flush=True)
        elif t in("SEND","RECV"):print(f"[{t}] peer={p['peer']} len={p['len']} first={p['first'][:64]}",flush=True);ev.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (sendmsg/recvmsg from libmetasec_ov)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump(ev,open(OUT,"w"),indent=1)
print(f"\n=== {len(ev)} MS datagrams -> {OUT}",flush=True)
peers=sorted(set(e["peer"] for e in ev))
for pr in peers:print("   peer:",pr,flush=True)

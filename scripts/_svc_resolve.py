import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 70
OFFS=json.load(open('scripts/_svc_all_offs.json'))
JS_TMPL=r"""
var OFFS=__OFFS__;
var TARGET="libmetasec_ov.so";
var NET={63:'read',64:'write',65:'readv',66:'writev',66:'writev',203:'connect',198:'socket',206:'sendto',207:'recvfrom',211:'sendmsg',212:'recvmsg',242:'accept4',204:'getsockname',205:'getpeername',210:'shutdown',200:'bind',201:'listen',202:'accept'};
var firstseen={};
function sockaddr(p){try{if(p.isNull())return"null";var fam=p.readU16();
 if(fam==2){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();return "IPv4 "+p.add(4).readU8()+"."+p.add(5).readU8()+"."+p.add(6).readU8()+"."+p.add(7).readU8()+":"+port;}
 if(fam==10){var port=(p.add(2).readU8()<<8)|p.add(3).readU8();var h="";for(var i=0;i<16;i++){h+=("0"+p.add(8+i).readU8().toString(16)).slice(-2);}return "IPv6 ["+h+"]:"+port;}
 if(fam==1){return "UNIX "+p.add(2).readCString();}
 return "fam"+fam;}catch(e){return"?"+e;}}
function attachAll(m){
 var base=m.base; var ok=0,err=0;
 OFFS.forEach(function(off){
  try{
   Interceptor.attach(base.add(off),{onEnter:function(a){
     var nr; try{nr=this.context.x8.toUInt32();}catch(e){return;}
     if(nr>512) return; // syscall nrs are small; skip garbage
     var key=off+":"+nr;
     if(!firstseen[key]){firstseen[key]=1; if(NET[nr]) send({tag:'R',off:off,nr:nr,name:NET[nr]});}
     if(nr==203||nr==200){ // connect/bind -> peer
       try{var peer=sockaddr(this.context.x1); send({tag:'C',off:off,nr:nr,name:NET[nr],fd:this.context.x0.toInt32(),peer:peer});}catch(e){}
     }
   }});
   ok++;
  }catch(e){err++;}
 });
 send({tag:'info',msg:'attached ok='+ok+' err='+err+' base='+base});
}
var done=false;
var iv=setInterval(function(){ if(done)return; var m=Process.findModuleByName(TARGET); if(m){done=true;clearInterval(iv);attachAll(m);} },20);
send({tag:'info',msg:'waiting for '+TARGET});
setInterval(function(){send({tag:'tick'});},15000);
"""
JS=JS_TMPL.replace("__OFFS__", json.dumps(OFFS))
resolves={}; conns=[]
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="tick":print("[tick]",flush=True)
        elif t=="R":
            k="0x%x"%p['off']; resolves[k]=(p['nr'],p['name']); print(f"[RESOLVE] off={k} nr={p['nr']} {p['name']}",flush=True)
        elif t=="C":
            conns.append(p); print(f"[CONNECT] off=0x{p['off']:x} {p['name']} fd={p['fd']} peer={p['peer']}",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (resolve 188 svc)",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
print("\n=== RESOLVED network svc sites ===",flush=True)
for k,(nr,nm) in sorted(resolves.items(),key=lambda x:x[0]):
    print(f"  {k}  nr={nr}  {nm}",flush=True)
print(f"\n=== distinct connect/bind peers ({len(conns)}) ===",flush=True)
seen=set()
for c in conns:
    key=(c['name'],c['peer'])
    if key in seen: continue
    seen.add(key); print(f"  {c['name']:8} {c['peer']}",flush=True)
json.dump({'resolves':{k:v for k,v in resolves.items()},'conns':conns}, open('scripts/_svc_resolved.json','w'))
try:s.detach()
except:pass

import frida,sys,time,json
PKG="com.zhiliaoapp.musically"
DUR=45
OFFS=json.load(open('scripts/_svc_all_offs.json'))[:5]  # first 5 svc
JS=r"""
var OFFS=__OFFS__; var TARGET="libmetasec_ov.so"; var seen={};
function attachAll(m){var base=m.base;var ok=0,err=0;
 OFFS.forEach(function(off){try{Interceptor.attach(base.add(off),{onEnter:function(a){
   var nr;try{nr=this.context.x8.toUInt32();}catch(e){return;}
   var k=off+':'+nr; if(!seen[k]){seen[k]=1; send({tag:'HIT',off:off,nr:nr});}
 }});ok++;}catch(e){err++;}});
 send({tag:'info',msg:'attached '+ok+'/'+OFFS.length+' err='+err+' base='+base});}
var done=false;var iv=setInterval(function(){if(done)return;var m=Process.findModuleByName(TARGET);if(m){done=true;clearInterval(iv);attachAll(m);}},20);
send({tag:'info',msg:'waiting'});
setInterval(function(){send({tag:'tick'});},10000);
"""
JS=JS.replace("__OFFS__",json.dumps(OFFS))
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="tick":print("[tick]",flush=True)
        elif t=="HIT":print(f"[HIT] off=0x{p['off']:x} nr={p['nr']}",flush=True)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s (test 5 svc: {[hex(x) for x in OFFS]})",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
print("[*] done",flush=True)

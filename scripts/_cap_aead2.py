import frida,sys,time,json,os
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 70
OUT=os.path.join(os.path.dirname(__file__),"..","ground-truth","getseed_aead_ce0516.json")
JS=r"""
function asc(p,n){try{var b=new Uint8Array(p.readByteArray(Math.min(n,1600)));var s="";for(var i=0;i<b.length;i++){var c=b[i];s+=(c>=32&&c<127)?String.fromCharCode(c):".";}return s;}catch(e){return"";}}
function hx(p,n){try{var b=new Uint8Array(p.readByteArray(Math.min(n,1600)));var h="";for(var i=0;i<b.length;i++)h+=("0"+b[i].toString(16)).slice(-2);return h;}catch(e){return"";}}
function interesting(s){return s.indexOf("get_seed")>=0||s.indexOf("/ms/")>=0||s.indexOf("mssdk")>=0||s.indexOf("device_platform")>=0||s.indexOf("ms_query")>=0;}
var lc=Process.findModuleByName("libcrypto.so");
var SEAL=lc.findExportByName("EVP_AEAD_CTX_seal");
var OPEN=lc.findExportByName("EVP_AEAD_CTX_open");
var nSeal=0,nOpen=0,hits=0,sizesOut={},sizesIn={};
Interceptor.attach(SEAL,{onEnter:function(a){try{
  nSeal++;var inl=a[7].toInt32();if(inl<=0||inl>200000)return;
  var b=Math.min(inl,63);sizesOut[b]=(sizesOut[b]||0)+1;
  var s=asc(a[6],inl);if(interesting(s)){hits++;send({tag:"SEAL",len:inl,ascii:s,hex:hx(a[6],inl)});}
}catch(e){}}});
Interceptor.attach(OPEN,{onEnter:function(a){this.out=a[1];this.olp=a[2];},onLeave:function(r){try{
  nOpen++;if(r.toInt32()!==1)return;var n=parseInt(this.olp.readU32());if(!n||n<=0||n>200000)return;
  var s=asc(this.out,n);if(interesting(s)){hits++;send({tag:"OPEN",len:n,ascii:s,hex:hx(this.out,n)});}
}catch(e){}}});
send({tag:"info",msg:"hooked seal@"+SEAL+" open@"+OPEN});
setInterval(function(){send({tag:"stat",seal:nSeal,open:nOpen,hits:hits});},8000);
"""
ev=[]
def om(m,d):
    if m.get("type")=="send":
        p=m["payload"];t=p["tag"]
        if t=="info":print("[*]",p["msg"],flush=True)
        elif t=="stat":print(f"[stat] seal_calls={p['seal']} open_calls={p['open']} hits={p['hits']}",flush=True)
        elif t in("SEAL","OPEN"):print(f"\n[+++ {t}] len={p['len']}\n  ascii={p['ascii'][:220]}\n  hex={p['hex'][:140]}",flush=True);ev.append(p)
    elif m.get("type")=="error":print("[ERR]",m.get("description"),flush=True)
dev=frida.get_usb_device(timeout=10)
print(f"[*] spawn {PKG} {DUR}s",flush=True)
pid=dev.spawn([PKG]);s=dev.attach(pid)
sc=s.create_script(JS);sc.on("message",om);sc.load();dev.resume(pid)
t0=time.time()
while time.time()-t0<DUR:time.sleep(0.5)
try:s.detach()
except:pass
json.dump(ev,open(OUT,"w"),indent=1)
print(f"\n=== {len(ev)} interesting -> {OUT}",flush=True)

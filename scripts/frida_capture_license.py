#!/usr/bin/env python3
# Capture license JSON musically 45.7.3: hook dispatcher 0x11a1e0 cmd=0x4000001, đọc arg5 (jstring = mảng JSON license).
# → dùng license app 1233 (khớp device-state musically) thay license_trill (1180) để test đóng gap 344→624.
import frida, time, sys
PKG="com.zhiliaoapp.musically"; OFF=0x11a1e0
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 30
JS=r"""
var LIB="libmetasec_ov.so", OFF=%d, PS=Process.pointerSize;
function tf(env,idx,ret,args){ return new NativeFunction(env.readPointer().add(idx*PS).readPointer(), ret, args); }
function GetStringUTFChars(env,s){ var p=tf(env,169,'pointer',['pointer','pointer','pointer'])(env,s,ptr(0)); return p.isNull()?null:p.readCString(); }
function install(){
    var m=Process.findModuleByName(LIB); if(!m) return false;
    send("HOOK 0x"+OFF.toString(16));
    Interceptor.attach(m.base.add(OFF),{
        onEnter:function(a){
            if((a[2].toInt32()>>>0)!==0x4000001) return;
            try{ var s=GetStringUTFChars(a[0], a[5]); send("LICENSE "+s); }catch(e){ send("err "+e); }
        }
    });
    return true;
}
if(Process.findModuleByName(LIB)) install();
else Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"),{onEnter:function(a){try{this.p=a[0].readCString();}catch(e){}},onLeave:function(r){if(this.p&&this.p.indexOf(LIB)>=0)install();}});
""" % OFF
got=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.startswith("LICENSE "):
            got.append(p[8:]); print("[+] LICENSE captured len=%d"%len(p[8:]))
        else: print("[*]",p[:100])
    elif m.get("type")=="error": print("[ERR]",m.get("description"))
def main():
    dev=frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — capture license ({DUR}s)")
    pid=dev.spawn([PKG]); s=dev.attach(pid); sc=s.create_script(JS); sc.on("message",on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except: pass
    if got:
        import os
        out=os.path.join(os.path.dirname(__file__),"..","..","mobile","unidbg","license_mus4573.json")
        open(out,"w",encoding="utf-8").write(got[0])
        print(f"[*] saved → {out}")
if __name__=="__main__": main()

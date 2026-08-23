#!/usr/bin/env python3
# Capture x-argus THẬT của phone: hook hàm sign nội bộ 0x9ecc0 (libmetasec 45.7.3, (url,cookie)->char* header).
# onLeave đọc return = "X-Argus\r\n...\r\nX-Gorgon\r\n..." → đo length X-Argus genuine để so với unidbg (344 vs 368).
import frida, time, sys, re
PKG = "com.zhiliaoapp.musically"; OFF = 0x9ecc0
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 40
JS = r"""
var LIB="libmetasec_ov.so", OFF=%d;
function install(){
    var m=Process.findModuleByName(LIB); if(!m) return false;
    send("HOOK sign 0x"+OFF.toString(16)+" base="+m.base);
    Interceptor.attach(m.base.add(OFF),{
        onEnter:function(a){ try{ this.url=a[0].readCString(); }catch(e){ this.url="?"; } },
        onLeave:function(ret){
            try{
                if(ret.isNull()) return;
                var s=ret.readCString();
                if(!s || s.indexOf("X-Argus")<0) return;
                send("SIGN url="+(this.url||"").slice(0,80));
                send("HDR "+s);
            }catch(e){ send("err "+e); }
        }
    });
    return true;
}
if(Process.findModuleByName(LIB)) install();
else Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"),{onEnter:function(a){try{this.p=a[0].readCString();}catch(e){}},onLeave:function(r){if(this.p&&this.p.indexOf(LIB)>=0)install();}});
""" % OFF
caps=[]
def on_message(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.startswith("HDR "):
            hdr=p[4:]; caps.append(hdr)
            def L(name):
                mm=re.search(name+r"\r?\n([^\r\n]+)", hdr); return len(mm.group(1)) if mm else -1
            print(f"[+] X-Argus len={L('X-Argus')}  X-Ladon len={L('X-Ladon')}  X-Gorgon len={L('X-Gorgon')}  X-Khronos len={L('X-Khronos')}")
        else: print("[*]", p[:120])
    elif m.get("type")=="error": print("[ERR]", m.get("description"))
def main():
    dev=frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — capture real sign 0x9ecc0 ({DUR}s). Mở app + lướt feed để trigger sign.")
    pid=dev.spawn([PKG]); s=dev.attach(pid); sc=s.create_script(JS); sc.on("message",on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except: pass
    if caps:
        import os
        out=os.path.join(os.path.dirname(__file__),"..","ground-truth","realsign_4573.txt")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out,"w",encoding="utf-8").write("\n\n".join(caps))
        print(f"[*] saved {len(caps)} sign captures → {out}")
if __name__=="__main__": main()

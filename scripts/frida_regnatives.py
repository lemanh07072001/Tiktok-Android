#!/usr/bin/env python3
# Hook RegisterNatives -> liet ke chinh xac cac ham native cua libmetasec_ov.so (45.9.3)
# cung ten Java method + signature + offset that trong lib.
import frida, sys, time

PKG = "com.zhiliaoapp.musically"

JS = r"""
var LIB = "libmetasec_ov.so";
var found = {};

function findRegisterNatives(){
    var art = Process.findModuleByName("libart.so");
    if(!art){ return null; }
    var syms = art.enumerateSymbols();
    var cand = null;
    for (var i=0;i<syms.length;i++){
        var n = syms[i].name;
        if (n.indexOf("RegisterNatives")>=0 && n.indexOf("CheckJNI")<0 && n.indexOf("Runtime")<0){
            // uu tien art::JNI::RegisterNatives
            if (n.indexOf("3JNI")>=0) return syms[i].address;
            cand = syms[i].address;
        }
    }
    return cand;
}

function hookRN(){
    var rn = findRegisterNatives();
    if(!rn){ send("KHONG tim thay RegisterNatives trong libart"); return false; }
    send("RegisterNatives @ "+rn);
    Interceptor.attach(rn, {
        onEnter: function(a){
            try {
                var methods = a[2];
                var count = a[3].toInt32();
                var meta = Process.findModuleByName(LIB);
                if(!meta) return;
                var lo = meta.base;
                var hi = meta.base.add(meta.size);
                var ps = Process.pointerSize;
                for (var i=0;i<count;i++){
                    var m = methods.add(i*ps*3);
                    var namep = m.readPointer();
                    var sigp  = m.add(ps).readPointer();
                    var fn    = m.add(2*ps).readPointer();
                    if (fn.compare(lo)>=0 && fn.compare(hi)<0){
                        var name = namep.isNull()? "?" : namep.readCString();
                        var sig  = sigp.isNull()? "?" : sigp.readCString();
                        var off  = fn.sub(lo);
                        var key = name+sig+off;
                        if(!found[key]){
                            found[key]=1;
                            send("NATIVE "+name+"  "+sig+"  -> "+LIB+"+0x"+off.toString(16)+" (abs "+fn+")");
                        }
                    }
                }
            } catch(e){ send("err onEnter: "+e); }
        }
    });
    return true;
}

// Hook som: cho libmetasec load qua dlopen roi hook RegisterNatives
var meta0 = Process.findModuleByName(LIB);
if (meta0){
    send(LIB+" da load base="+meta0.base+" size="+meta0.size);
}
// RegisterNatives co the da/ chua goi; hook ngay
hookRN();

// Bat dlopen de biet luc metasec load (neu spawn)
try {
    var dl = Module.findGlobalExportByName("android_dlopen_ext");
    if (dl){
        Interceptor.attach(dl, {
            onEnter: function(a){ try{ this.p=a[0].readCString(); }catch(e){ this.p=""; } },
            onLeave: function(r){
                if (this.p && this.p.indexOf(LIB)>=0){
                    var m = Process.findModuleByName(LIB);
                    if(m) send(LIB+" LOADED base="+m.base+" size="+m.size+" (JNI_OnLoad sap chay)");
                }
            }
        });
    }
} catch(e){}
"""

def on_message(m, d):
    if m.get("type") == "send":
        print(m["payload"])
    elif m.get("type") == "error":
        print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    print("[*] Spawn", PKG)
    pid = dev.spawn([PKG])
    session = dev.attach(pid)
    sc = session.create_script(JS)
    sc.on("message", on_message)
    sc.load()
    dev.resume(pid)
    print("[*] Resumed, thu thap 30s...")
    time.sleep(30)
    try: session.detach()
    except: pass

if __name__ == "__main__":
    main()

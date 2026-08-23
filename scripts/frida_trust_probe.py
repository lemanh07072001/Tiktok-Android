#!/usr/bin/env python3
# Trust probe: metasec doc property/fingerprint nao + check file root nao (khi dung attestation).
import frida, time

PKG = "com.zhiliaoapp.musically"

JS = r"""
var META = null;
function meta(){ if(!META) META=Process.findModuleByName("libmetasec_ov.so"); return META; }
function inMeta(a){ var m=meta(); return m && a && a.compare(m.base)>=0 && a.compare(m.base.add(m.size))<0; }
function metaOff(a){ return inMeta(a) ? ("libmetasec+0x"+a.sub(meta().base).toString(16)) : null; }
function G(n){ try{return Module.findGlobalExportByName(n);}catch(e){return null;} }

// props nhay cam (security/emulator/debug)
function interesting(n){
    return /fingerprint|debuggable|ro\.secure|adb|qemu|goldfish|ranchu|su|magisk|selinux|tags|type|bootmode|kernel|hardware|product\.(model|brand|device|manufacturer)|build\.(host|user|id)|serialno|boot\.verifiedboot|vbmeta|dalvik.vm/i.test(n);
}

var seenP={};
var pGet=G("__system_property_get");
if(pGet) Interceptor.attach(pGet,{
    onEnter:function(a){ try{ this.name=a[0].readCString(); this.buf=a[1]; }catch(e){} this.ret=this.returnAddress; },
    onLeave:function(r){
        if(!this.name) return;
        var fromMeta = inMeta(this.ret);
        if(!fromMeta && !interesting(this.name)) return;
        var val=""; try{ val=this.buf.readCString(); }catch(e){}
        var key=this.name+"|"+fromMeta;
        if(seenP[key]) return; seenP[key]=1;
        send((fromMeta?">>> META prop":"    prop")+" "+this.name+" = \""+val+"\""+(fromMeta?(" @"+metaOff(this.ret)):""));
    }
});

// file access (root/frida detection) — co the bi direct-syscall ne, nhung thu
var seenF={};
function hookAcc(name){
    var p=G(name); if(!p) return;
    Interceptor.attach(p,{
        onEnter:function(a){
            var pathArg = (name==="faccessat")? a[1] : a[0];
            var path=""; try{ path=pathArg.readCString(); }catch(e){ return; }
            var ret=this.returnAddress;
            var fromMeta=inMeta(ret);
            if(!fromMeta) return;
            var key=path; if(seenF[key]) return; seenF[key]=1;
            send(">>> META "+name+" \""+path+"\" @"+metaOff(ret));
        }
    });
}
hookAcc("access"); hookAcc("faccessat"); hookAcc("stat"); hookAcc("__openat");

// dispatcher hook — gan khi metasec load qua dlopen
var dispHooked=false;
function hookDisp(){
    if(dispHooked) return; var m=meta(); if(!m) return; dispHooked=true;
    var sign=0, other=0;
    Interceptor.attach(m.base.add(0x11c580),{
        onEnter:function(a){ if((a[2].toInt32()>>>24)>=4) sign++; else other++; }
    });
    setInterval(function(){ send("dispatcher: sign-cat="+sign+" other="+other); }, 8000);
    send("libmetasec LOADED base="+m.base+" -> dispatcher hooked");
}
if(meta()){ hookDisp(); }
else {
    var dl=G("android_dlopen_ext");
    if(dl) Interceptor.attach(dl,{
        onEnter:function(a){ try{this.p=a[0].readCString();}catch(e){this.p="";} },
        onLeave:function(r){ if(this.p&&this.p.indexOf("libmetasec_ov.so")>=0){ hookDisp(); } }
    });
}
send("hooks: prop="+pGet+" (cho metasec load...)");
"""

def on_message(m, d):
    if m.get("type") == "send": print(m["payload"])
    elif m.get("type") == "error": print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    pid = dev.spawn([PKG]); session = dev.attach(pid)
    sc = session.create_script(JS); sc.on("message", on_message); sc.load()
    dev.resume(pid)
    print("[*] theo doi 32s...")
    time.sleep(32)
    try: session.detach()
    except: pass

if __name__ == "__main__":
    main()

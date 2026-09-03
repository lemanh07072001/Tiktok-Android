#!/usr/bin/env python3
# Buoc 1 breakthrough — capture CHUOI INIT metasec: dump DAY DU args cua
# 0x4000001 (init), 0x4000002, nhom 0x2000002/3/4/9 + 0x5000001, theo dung thu tu cold-start.
# Muc tieu: biet chinh xac cac lenh + args de REPLAY trong unidbg -> populate ctx+0x690 (SDK init).
import frida, time, sys

PKG = "com.zhiliaoapp.musically"
OFF = 0x11a1e0
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 35
# cmd quan tam cho init (bo qua 0x1000001 decrypt-string spam)
WANT = [0x4000001, 0x4000002, 0x2000001, 0x2000002, 0x2000003, 0x2000004,
        0x2000005, 0x2000006, 0x2000007, 0x2000008, 0x2000009, 0x200000a, 0x5000001, 0x3000001, 0x1000003]

JS = r"""
var LIB="libmetasec_ov.so", OFF=%d, PS=Process.pointerSize, seq=0;
var WANT=%s;
function tblFn(env,idx,ret,args){ var p=env.readPointer().add(idx*PS).readPointer(); return new NativeFunction(p,ret,args); }
function FindClass(env,n){ return tblFn(env,6,'pointer',['pointer','pointer'])(env, Memory.allocUtf8String(n)); }
function IsInstanceOf(env,o,c){ return tblFn(env,32,'uint8',['pointer','pointer','pointer'])(env,o,c)!=0; }
function GetStringUTFChars(env,j){ var p=tblFn(env,169,'pointer',['pointer','pointer','pointer'])(env,j,ptr(0)); return p.isNull()?null:p.readCString(); }
function GetArrayLength(env,a){ return tblFn(env,171,'int',['pointer','pointer'])(env,a); }
function GetByteArrayElements(env,a){ return tblFn(env,184,'pointer',['pointer','pointer','pointer'])(env,a,ptr(0)); }
function GetObjectClass(env,o){ return tblFn(env,31,'pointer',['pointer','pointer'])(env,o); }
function hx(p,n){ var b=new Uint8Array(p.readByteArray(n)); var h=""; for(var i=0;i<n;i++)h+=("0"+b[i].toString(16)).slice(-2); return h; }
function clsName(env,obj){
    try { var cls=GetObjectClass(env,obj);
        var clsCls=FindClass(env,"java/lang/Class");
        var mid=tblFn(env,33,'pointer',['pointer','pointer','pointer','pointer'])(env,clsCls,Memory.allocUtf8String("getName"),Memory.allocUtf8String("()Ljava/lang/String;"));
        var js=tblFn(env,34,'pointer',['pointer','pointer','pointer'])(env,cls,mid);
        return GetStringUTFChars(env,js);
    } catch(e){ return "?"; }
}
function desc(env,obj){
    if(!obj||obj.isNull()) return "null";
    try {
        if(IsInstanceOf(env,obj,FindClass(env,"java/lang/String"))) return "String=\""+GetStringUTFChars(env,obj)+"\"";
        if(IsInstanceOf(env,obj,FindClass(env,"[B"))){ var l=GetArrayLength(env,obj),p=GetByteArrayElements(env,obj),c=l>2048?2048:l; return "byte["+l+"]="+hx(p,c)+(l>c?"...":""); }
        return "(obj:"+clsName(env,obj)+")";
    } catch(e){ return "(desc err "+e+")"; }
}
function install(){
    var m=Process.findModuleByName(LIB); if(!m) return false;
    send("HOOK "+m.base.add(OFF)+" base="+m.base);
    Interceptor.attach(m.base.add(OFF),{
        onEnter:function(a){
            this.cmd=a[2].toInt32(); this.env=a[0];
            if(WANT.indexOf(this.cmd>>>0)<0){ this.skip=true; return; }
            this.skip=false; this.n=++seq;
            var s=null; try{ if(!a[5].isNull()) s=GetStringUTFChars(a[0],a[5]); }catch(e){}
            send("\n[SEQ "+this.n+"] cmd=0x"+(this.cmd>>>0).toString(16)+" i2="+a[3].toInt32()+" long="+a[4]);
            if(s!=null) send("   STR("+s.length+")="+(s.length>1200?s.substring(0,1200)+"...":s));
            send("   OBJ5="+desc(a[0],a[5]));
            send("   OBJ6="+desc(a[0],a[6]));
        },
        onLeave:function(ret){
            if(this.skip) return;
            send("   RET["+this.n+" cmd=0x"+(this.cmd>>>0).toString(16)+"]="+desc(this.env,ret));
        }
    });
    return true;
}
if(Process.findModuleByName(LIB)) install();
else { var dl=Module.findGlobalExportByName("android_dlopen_ext"); Interceptor.attach(dl,{onEnter:function(a){try{this.p=a[0].readCString();}catch(e){this.p="";}},onLeave:function(r){if(this.p&&this.p.indexOf(LIB)>=0)install();}}); send("cho load..."); }
""" % (OFF, str([x for x in WANT]))

def on_message(m, d):
    if m.get("type") == "send": print(m["payload"])
    elif m.get("type") == "error": print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — capture init sequence {DUR}s")
    pid = dev.spawn([PKG]); s = dev.attach(pid)
    sc = s.create_script(JS); sc.on("message", on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except: pass

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Capture interface sign cmd 0x5000001 @ dispatcher 0x11a1e0 (45.7.3): dump String[] input (onEnter)
# + output (onLeave, đọc lại String[] xem headers ký được ghi back). → biết cách gọi sign trong unidbg.
import frida, time, sys
PKG = "com.zhiliaoapp.musically"; OFF = 0x11a1e0
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 35
JS = r"""
var LIB="libmetasec_ov.so", OFF=%d, PS=Process.pointerSize, n=0;
function tf(env,idx,ret,args){ return new NativeFunction(env.readPointer().add(idx*PS).readPointer(), ret, args); }
function GetArrayLength(env,a){ return tf(env,171,'int',['pointer','pointer'])(env,a); }
function GetObjectArrayElement(env,a,i){ return tf(env,173,'pointer',['pointer','pointer','int'])(env,a,i); }
function GetStringUTFChars(env,s){ var p=tf(env,169,'pointer',['pointer','pointer','pointer'])(env,s,ptr(0)); return p.isNull()?null:p.readCString(); }
function IsInstanceOf(env,o,c){ return tf(env,32,'uint8',['pointer','pointer','pointer'])(env,o,c)!=0; }
function FindClass(env,nm){ return tf(env,6,'pointer',['pointer','pointer'])(env,Memory.allocUtf8String(nm)); }
function dumpArr(env,arr,tag){
    if(arr.isNull()) { send(tag+" null"); return; }
    try {
        var strArrCls=FindClass(env,"[Ljava/lang/String;");
        if(!IsInstanceOf(env,arr,strArrCls)){ send(tag+" not-String[]"); return; }
        var len=GetArrayLength(env,arr);
        send(tag+" String["+len+"]:");
        for(var i=0;i<len && i<20;i++){
            var el=GetObjectArrayElement(env,arr,i);
            var s=el.isNull()?"null":GetStringUTFChars(env,el);
            if(s && s.length>300) s=s.substring(0,300)+"...";
            send("   ["+i+"]="+s);
        }
    } catch(e){ send(tag+" err "+e); }
}
function install(){
    var m=Process.findModuleByName(LIB); if(!m) return false;
    send("HOOK 0x"+OFF.toString(16)+" base="+m.base);
    Interceptor.attach(m.base.add(OFF),{
        onEnter:function(a){
            this.cmd=a[2].toInt32(); this.env=a[0]; this.arr=a[6];
            if((this.cmd>>>0)!==0x5000001){ this.skip=true; return; }
            this.skip=false; this.n=++n;
            send("\n=== SIGN #"+this.n+" cmd=0x5000001 i2="+a[3].toInt32()+" long="+a[4]+" a5="+a[5]);
            dumpArr(a[0], a[6], "IN arg6");
            dumpArr(a[0], a[5], "IN arg5");
        },
        onLeave:function(ret){
            if(this.skip) return;
            send("RET#"+this.n+"="+ret);
            dumpArr(this.env, this.arr, "OUT arg6(after)");
        }
    });
    return true;
}
if(Process.findModuleByName(LIB)) install();
else { Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"),{onEnter:function(a){try{this.p=a[0].readCString();}catch(e){}},onLeave:function(r){if(this.p&&this.p.indexOf(LIB)>=0)install();}}); }
""" % OFF
def on_message(m,d):
    if m.get("type")=="send": print(m["payload"])
    elif m.get("type")=="error": print("[ERR]",m.get("description"))
def main():
    dev=frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — capture sign 0x5000001 ({DUR}s)")
    pid=dev.spawn([PKG]); s=dev.attach(pid); sc=s.create_script(JS); sc.on("message",on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except: pass
if __name__=="__main__": main()

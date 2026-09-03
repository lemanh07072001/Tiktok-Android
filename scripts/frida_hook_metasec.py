#!/usr/bin/env python3
# Hook dispatcher metasec a() @ libmetasec_ov.so+0x11c580 (45.9.3).
# Doc args/return qua bang ham JNI truc tiep (frida17 bo global Java).
import frida, time

PKG = "com.zhiliaoapp.musically"
OFF = 0x11c580

JS = r"""
var LIB="libmetasec_ov.so";
var OFF=%d;
var PS=Process.pointerSize;
var callN=0;
var hist={};

// ---- JNI helpers qua function table (env = con tro toi bang ham) ----
function tblFn(env, idx, ret, args){
    var table = env.readPointer();
    var p = table.add(idx*PS).readPointer();
    return new NativeFunction(p, ret, args);
}
function FindClass(env, name){
    var s = Memory.allocUtf8String(name);
    return tblFn(env,6,'pointer',['pointer','pointer'])(env, s);
}
function IsInstanceOf(env, obj, cls){
    return tblFn(env,32,'uint8',['pointer','pointer','pointer'])(env, obj, cls) != 0;
}
function GetStringUTFChars(env, jstr){
    var p = tblFn(env,169,'pointer',['pointer','pointer','pointer'])(env, jstr, ptr(0));
    return p.isNull()? null : p.readCString();
}
function GetArrayLength(env, arr){
    return tblFn(env,171,'int',['pointer','pointer'])(env, arr);
}
function GetByteArrayElements(env, arr){
    return tblFn(env,184,'pointer',['pointer','pointer','pointer'])(env, arr, ptr(0));
}
function describe(env, obj){
    if(!obj || obj.isNull()) return "null";
    try {
        var strCls = FindClass(env, "java/lang/String");
        if(IsInstanceOf(env, obj, strCls)){
            var s = GetStringUTFChars(env, obj);
            return "String("+(s?s.length:0)+")=\""+(s&&s.length>2000?s.substring(0,2000)+"...":s)+"\"";
        }
        var baCls = FindClass(env, "[B");
        if(IsInstanceOf(env, obj, baCls)){
            var len = GetArrayLength(env, obj);
            var p = GetByteArrayElements(env, obj);
            var cap = len>512?512:len;
            var bytes = new Uint8Array(p.readByteArray(cap));
            var hex=""; for(var i=0;i<cap;i++){ hex+=("0"+bytes[i].toString(16)).slice(-2); }
            return "byte["+len+"]="+hex+(len>96?"...":"");
        }
        return "(obj)";
    } catch(e){ return "(desc err "+e+")"; }
}

function install(){
    var m = Process.findModuleByName(LIB);
    if(!m) return false;
    var target = m.base.add(OFF);
    send("HOOK a() @ "+target+" base="+m.base+" +0x"+OFF.toString(16));
    Interceptor.attach(target, {
        onEnter: function(a){
            callN++;
            this.n=callN;
            this.env=a[0];
            this.cmd=a[2].toInt32();
            this.i2=a[3].toInt32();
            this.l=a[4];
            this.s5=a[5];
            this.o6=a[6];
            hist[this.cmd]=(hist[this.cmd]||0)+1;
            var cat = this.cmd >>> 24;         // byte cao = nhom
            this.sign = (cat >= 4);            // 0x04+/0x05+ = ky/token/report
            var str=null;
            try{ if(!a[5].isNull()){ str=GetStringUTFChars(a[0], a[5]); } }catch(e){}
            this.str=str;
            // chi in day du nhom KY, hoac string dai bat thuong
            if(this.sign || (str && str.length>60)){
                var od = describe(a[0], a[6]);
                send("\n>>> CALL#"+this.n+" cmd=0x"+this.cmd.toString(16)+" ("+this.cmd+") i2="+this.i2+" long="+this.l);
                if(str) send("    ARG_STR("+str.length+")="+str);
                if(od!="null") send("    ARG_OBJ="+od);
            }
        },
        onLeave: function(ret){
            if(!this.sign) return;
            var rd = describe(this.env, ret);
            if(rd && rd!="null"){
                send("    RET#"+this.n+" cmd=0x"+this.cmd.toString(16)+" -> "+rd);
            }
        }
    });
    return true;
}

if(Process.findModuleByName(LIB)){ install(); }
else {
    var dl=Module.findGlobalExportByName("android_dlopen_ext");
    Interceptor.attach(dl,{
        onEnter:function(a){ try{this.p=a[0].readCString();}catch(e){this.p="";} },
        onLeave:function(r){ if(this.p&&this.p.indexOf(LIB)>=0){ install(); } }
    });
    send("cho "+LIB+" load...");
}

// histogram moi 10s
setInterval(function(){
    var s="HIST cmd:count = ";
    for(var k in hist){ s+=k+":"+hist[k]+" "; }
    send(s);
}, 10000);
""" % OFF

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
    print("[*] Theo doi 45s...")
    time.sleep(45)
    try: session.detach()
    except: pass

if __name__ == "__main__":
    main()

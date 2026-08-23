#!/usr/bin/env python3
# Track A — Hook dispatcher THAT cua 45.7.3: a(I,I,J,String,Object):Object @ libmetasec+0x11a1e0
# (lay tu RegisterNatives, KHONG phai 0x11c580=netlink). Doc args/return qua JNI function table (frida17).
# Muc tieu: khi app goi get_seed luc cold-start -> bat cmd nao dung, dump byte[] ~112B (attestation).
import frida, time, sys

PKG = "com.zhiliaoapp.musically"
OFF = 0x11a1e0
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 40

JS = r"""
var LIB="libmetasec_ov.so";
var OFF=%d;
var PS=Process.pointerSize;
var callN=0, hist={};

function tblFn(env, idx, ret, args){
    var p = env.readPointer().add(idx*PS).readPointer();
    return new NativeFunction(p, ret, args);
}
function FindClass(env,n){ return tblFn(env,6,'pointer',['pointer','pointer'])(env, Memory.allocUtf8String(n)); }
function IsInstanceOf(env,o,c){ return tblFn(env,32,'uint8',['pointer','pointer','pointer'])(env,o,c)!=0; }
function GetStringUTFChars(env,j){ var p=tblFn(env,169,'pointer',['pointer','pointer','pointer'])(env,j,ptr(0)); return p.isNull()?null:p.readCString(); }
function GetArrayLength(env,a){ return tblFn(env,171,'int',['pointer','pointer'])(env,a); }
function GetByteArrayElements(env,a){ return tblFn(env,184,'pointer',['pointer','pointer','pointer'])(env,a,ptr(0)); }

function hexOf(p, n){ var b=new Uint8Array(p.readByteArray(n)); var h=""; for(var i=0;i<n;i++){h+=("0"+b[i].toString(16)).slice(-2);} return h; }
function describe(env,obj){
    if(!obj||obj.isNull()) return "null";
    try {
        if(IsInstanceOf(env,obj,FindClass(env,"java/lang/String"))){
            var s=GetStringUTFChars(env,obj);
            return "String("+(s?s.length:0)+")=\""+(s&&s.length>800?s.substring(0,800)+"...":s)+"\"";
        }
        if(IsInstanceOf(env,obj,FindClass(env,"[B"))){
            var len=GetArrayLength(env,obj), p=GetByteArrayElements(env,obj);
            var cap=len>1024?1024:len;
            var flag = (len>=90 && len<=140) ? "  <== CANDIDATE_112B" : "";
            return "byte["+len+"]"+flag+"="+hexOf(p,cap)+(len>cap?"...":"");
        }
        return "(obj)";
    } catch(e){ return "(desc err "+e+")"; }
}

function install(){
    var m=Process.findModuleByName(LIB); if(!m) return false;
    var t=m.base.add(OFF);
    send("HOOK a() @ "+t+" base="+m.base+" +0x"+OFF.toString(16));
    Interceptor.attach(t,{
        onEnter:function(a){
            callN++; this.n=callN; this.env=a[0];
            this.cmd=a[2].toInt32(); this.i2=a[3].toInt32(); this.l=a[4]; this.s5=a[5]; this.o6=a[6];
            hist[this.cmd]=(hist[this.cmd]||0)+1;
            var cat=this.cmd>>>24; this.sign=(cat>=4);
            var str=null; try{ if(!a[5].isNull()) str=GetStringUTFChars(a[0],a[5]); }catch(e){}
            this.str=str;
            // In: nhom KY (cat>=4) hoac co String dai (URL/header)
            if(this.sign || (str && str.length>40)){
                var od=describe(a[0], a[6]);
                send("\n>>> #"+this.n+" cmd=0x"+this.cmd.toString(16)+" i2="+this.i2+" long="+this.l);
                if(str) send("    STR("+str.length+")="+(str.length>600?str.substring(0,600)+"...":str));
                if(od!="null") send("    OBJ="+od);
            }
        },
        onLeave:function(ret){
            if(!this.sign) return;
            var rd=describe(this.env, ret);
            if(rd&&rd!="null") send("    RET#"+this.n+" cmd=0x"+this.cmd.toString(16)+" -> "+rd);
        }
    });
    return true;
}

if(Process.findModuleByName(LIB)){ install(); }
else {
    var dl=Module.findGlobalExportByName("android_dlopen_ext");
    Interceptor.attach(dl,{ onEnter:function(a){try{this.p=a[0].readCString();}catch(e){this.p="";}},
        onLeave:function(r){ if(this.p&&this.p.indexOf(LIB)>=0) install(); }});
    send("cho "+LIB+" load...");
}
setInterval(function(){ var s="HIST cmd:count = "; for(var k in hist){ s+="0x"+(parseInt(k)>>>0).toString(16)+":"+hist[k]+" "; } send(s); }, 8000);
""" % OFF

def on_message(m, d):
    if m.get("type") == "send": print(m["payload"])
    elif m.get("type") == "error": print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} (dispatcher 0x{OFF:x}, {DUR}s)")
    pid = dev.spawn([PKG])
    session = dev.attach(pid)
    sc = session.create_script(JS)
    sc.on("message", on_message)
    sc.load()
    dev.resume(pid)
    time.sleep(DUR)
    try: session.detach()
    except: pass

if __name__ == "__main__":
    main()

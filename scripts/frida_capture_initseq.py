#!/usr/bin/env python3
# Capture the FULL genuine metasec init sequence from a live phone (musically 45.7.3).
# Hooks dispatcher 0x11a1e0, logs EVERY call's cmd + arg shapes, and captures the license
# (cmd 0x4000001, arg d = a[5], a JSON-array string). Purpose: feed the license + replicate
# the exact offline init in tt.Dump to unlock inner-report #16/#17 (task b / option A1).
#
# SECURITY: values (license, did/iid) are written ONLY to cap.noindex/ (hard git-ignored).
# stdout prints cmd + arg-shape + LENGTHS only — never the values. Passive hook of the app's
# own init argument; no login automation, no server replay.
#
# Usage:  python scripts/frida_capture_initseq.py [seconds]
import frida, time, sys, os, json
from collections import Counter

PKG = "com.zhiliaoapp.musically"
OFF = 0x11a1e0
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 40
OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cap.noindex", "license_capture")

JS = r"""
var LIB="libmetasec_ov.so", OFF=%d, PS=Process.pointerSize;
function tf(env,idx,ret,args){ return new NativeFunction(env.readPointer().add(idx*PS).readPointer(), ret, args); }
function GetStringUTFChars(env,s){ if(s.isNull())return null;
    var p=tf(env,169,'pointer',['pointer','pointer','pointer'])(env,s,ptr(0));
    return p.isNull()?null:p.readCString(); }
function install(){
    var m=Process.findModuleByName(LIB); if(!m) return false;
    send({t:"hook", off:OFF});
    Interceptor.attach(m.base.add(OFF),{
        onEnter:function(a){
            var cmd=a[2].toInt32()>>>0, b=a[3].toInt32(), c=a[4].toInt32();
            var rec={t:"call", cmd:cmd, b:b, c:c, dstr:null, e:"?"};
            try{ var s=GetStringUTFChars(a[0],a[5]); if(s!==null) rec.dstr=s; }catch(e){}
            try{ rec.e = a[6].isNull()? "null":"obj"; }catch(e){ rec.e="?"; }
            send(rec);
        }
    });
    return true;
}
if(Process.findModuleByName(LIB)) install();
else Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"),{
    onEnter:function(a){try{this.p=a[0].readCString();}catch(e){}},
    onLeave:function(r){if(this.p&&this.p.indexOf(LIB)>=0)install();}});
""" % OFF

calls = []
license_val = [None]

def on_message(m, d):
    if m.get("type") == "send":
        p = m["payload"]
        if isinstance(p, dict) and p.get("t") == "call":
            calls.append(p)
            cmd = p["cmd"]; ds = p.get("dstr")
            if cmd == 0x4000001 and ds:
                license_val[0] = ds
                print(f"[+] 0x4000001 LICENSE captured (arg d len={len(ds)}) e={p.get('e')}")
            else:
                dl = f"str[len={len(ds)}]" if ds else "null/nonstr"
                print(f"[*] cmd=0x{cmd:x} b={p['b']} c={p['c']} d={dl} e={p.get('e')}")
        elif isinstance(p, dict) and p.get("t") == "hook":
            print(f"[*] hooked 0x{p['off']:x}")
        else:
            print("[*]", str(p)[:80])
    elif m.get("type") == "error":
        print("[ERR]", m.get("description"))

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — capture init seq ({DUR}s)")
    pid = dev.spawn([PKG]); s = dev.attach(pid)
    sc = s.create_script(JS); sc.on("message", on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except Exception: pass

    if license_val[0]:
        lp = os.path.join(OUTDIR, "license_mus4573.json")
        open(lp, "w", encoding="utf-8").write(license_val[0])
        print(f"[*] license saved -> {os.path.normpath(lp)} (len={len(license_val[0])})")
    else:
        print("[!] NO license captured (cmd 0x4000001 arg d never a string within window)")

    tp = os.path.join(OUTDIR, "init_transcript.json")
    json.dump(calls, open(tp, "w", encoding="utf-8"), indent=1)
    print(f"[*] init transcript saved -> {os.path.normpath(tp)} ({len(calls)} calls)")
    print("[*] cmd histogram:", {hex(k): v for k, v in Counter(c['cmd'] for c in calls).items()})

if __name__ == "__main__":
    main()

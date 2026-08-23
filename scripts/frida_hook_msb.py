#!/usr/bin/env python3
# B — Hook Java MS.b(cmd,...) tren phone that: capture GIA TRI THAT cua device-signal callbacks
#   (0x10003/0x100003f/0x1000011...) ma unidbg tra null → biet x-argus device-state thieu gi.
import frida, time, sys

PKG = "com.zhiliaoapp.musically"
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 30

JS = r"""
Java.perform(function() {
    try {
        var MS = Java.use("com.bytedance.mobsec.metasec.ov.MS");
        var ov = MS.b.overloads;
        send("MS.b overloads: " + ov.length);
        ov.forEach(function(m) {
            m.implementation = function() {
                var args = arguments;
                var ret;
                try { ret = m.apply(this, args); } catch(e) { ret = null; }
                try {
                    var cmd = args.length>0 ? (args[0]>>>0) : 0;
                    var ch = cmd.toString(16);
                    // device-signal cmds (0x1xxxxxx nhom thap, khong phai decrypt 0x1000001)
                    var want = ['10003','100003f','1000011','1000012','1000013','100000f','1000010','1000014','1000015','1000016','1000021','1000022','1000023'];
                    if (want.indexOf(ch) >= 0) {
                        var s = args.length>3 ? (""+args[3]) : "";
                        var r = (ret===null||ret===undefined) ? "null" : (""+ret);
                        if (r.length>240) r = r.substring(0,240)+"...";
                        send("MS.b(0x"+ch+" a2="+args[1]+" s="+(s.length>50?s.substring(0,50):s)+") => "+r);
                    }
                } catch(e) { send("log err "+e); }
                return ret;
            };
        });
        send("hooked MS.b");
    } catch(e) { send("MS class err: "+e); }
});
"""

def on_message(m, d):
    if m.get("type") == "send": print(m["payload"])
    elif m.get("type") == "error": print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} ({DUR}s) — hook MS.b device-signals")
    pid = dev.spawn([PKG]); s = dev.attach(pid)
    sc = s.create_script(JS); sc.on("message", on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except: pass

if __name__ == "__main__":
    main()

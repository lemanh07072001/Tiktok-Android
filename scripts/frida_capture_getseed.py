#!/usr/bin/env python3
# Hook SSL_write (plaintext trước TLS) → capture get_seed request (URL + headers x-argus + body 112B)
# cho device HIỆN TẠI (khớp device-state đã extract). Native hook, không cần Java-bridge.
import frida, time, sys, base64

PKG = "com.zhiliaoapp.musically"
DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 40

JS = r"""
var found = {};
function hookSSL(name) {
    var p = Module.findGlobalExportByName(name);
    if (!p) { for (var _m of ["libssl.so","libttboringssl.so","libsscronet.so"]) { var mm = Process.findModuleByName(_m); if (mm) { var e = mm.findExportByName(name); if (e) { p = e; break; } } } }
    if (!p) return false;
    Interceptor.attach(p, {
        onEnter: function (a) {
            try {
                var num = a[2].toInt32();
                if (num <= 0 || num > 200000) return;
                var bytes = new Uint8Array(a[1].readByteArray(num));
                // decode ascii-ish để tìm request-line/headers
                var head = "";
                for (var i = 0; i < Math.min(num, 400); i++) head += String.fromCharCode(bytes[i] & 0x7f);
                if (head.indexOf("get_seed") >= 0 || head.indexOf("/ms/") >= 0) {
                    var hex = ""; for (var j = 0; j < num; j++) hex += ("0" + bytes[j].toString(16)).slice(-2);
                    send({ tag: "GETSEED_" + name, len: num, hex: hex });
                }
            } catch (e) {}
        }
    });
    return true;
}
["SSL_write", "SSL_write_ex"].forEach(function (n) { if (hookSSL(n)) send({ tag: "hooked", name: n }); });
"""

parts = []
def on_message(m, d):
    if m.get("type") == "send":
        p = m["payload"]
        if isinstance(p, dict) and p.get("tag", "").startswith("GETSEED"):
            print(f"[+] {p['tag']} len={p['len']}")
            parts.append(p["hex"])
        else:
            print("[*]", p)
    elif m.get("type") == "error":
        print("[ERR]", m.get("description"))

def main():
    dev = frida.get_usb_device(timeout=10)
    print(f"[*] Spawn {PKG} — capture get_seed via SSL_write ({DUR}s)")
    pid = dev.spawn([PKG]); s = dev.attach(pid)
    sc = s.create_script(JS); sc.on("message", on_message); sc.load(); dev.resume(pid)
    time.sleep(DUR)
    try: s.detach()
    except: pass
    if parts:
        import os
        out = os.path.join(os.path.dirname(__file__), "..", "ground-truth", "getseed_7664_raw.txt")
        with open(out, "w") as f: f.write("\n".join(parts))
        print(f"[*] saved {len(parts)} SSL_write chunks → {out}")

if __name__ == "__main__":
    main()

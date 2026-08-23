#!/usr/bin/env python3
# Quet bo nho app tim byte seed (attach vao app dang chay).
import frida, re, time, sys

PKG = "com.zhiliaoapp.musically"
TARGET = int(sys.argv[1]) if len(sys.argv) > 1 else "TikTok"

# doc seed hex tu file
seed_hex = None
for line in open(r"e:\tiktok_signer\CAPTURED_DYN_SEED.txt", encoding="utf-8"):
    if line.startswith("hex="):
        seed_hex = line.strip()[4:]
if not seed_hex:
    raise SystemExit("khong doc duoc seed hex")

# dung 24 byte dau lam pattern (du unique)
prefix = seed_hex[:48]
pattern = " ".join(prefix[i:i+2] for i in range(0, len(prefix), 2))
print("[*] Seed prefix pattern (24B):", pattern[:60], "...")
print("[*] Full seed len:", len(seed_hex)//2, "bytes")

JS = r"""
var pattern = "%s";
var fullHex = "%s";
send("bat dau scan pattern 24B...");
var ranges = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
send("so ranges: "+ranges.length);
var found=0;
ranges.forEach(function(rg){
    try{
        var res = Memory.scanSync(rg.base, rg.size, pattern);
        res.forEach(function(m){
            found++;
            // xac nhan full 176B
            var full=true;
            try{
                var bytes = new Uint8Array(m.address.readByteArray(fullHex.length/2));
                for(var i=0;i<fullHex.length/2;i++){
                    var b = parseInt(fullHex.substr(i*2,2),16);
                    if(bytes[i]!==b){ full=false; break; }
                }
            }catch(e){ full=false; }
            var mod = Process.findModuleByAddress(m.address);
            var loc = mod ? (mod.name+"+0x"+m.address.sub(mod.base).toString(16)) : ("anon "+rg.protection);
            send("HIT @ "+m.address+" full176="+full+" region="+loc+" prot="+rg.protection);
        });
    }catch(e){}
});
send("=> tong hit: "+found);
""" % (pattern, seed_hex)

def on_message(m, d):
    if m.get("type") == "send": print(m["payload"])
    elif m.get("type") == "error": print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    session = dev.attach(TARGET)
    sc = session.create_script(JS); sc.on("message", on_message); sc.load()
    time.sleep(8)
    session.detach()

if __name__ == "__main__":
    main()

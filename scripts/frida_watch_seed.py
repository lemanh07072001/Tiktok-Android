#!/usr/bin/env python3
# Watchpoint: MemoryAccessMonitor tren vung seed + hook dispatcher ky (0x11c580).
# Chung minh libmetasec DOC seed khi dung X-Argus.
import frida, time, sys

seed_hex = None
for line in open(r"e:\tiktok_signer\CAPTURED_DYN_SEED.txt", encoding="utf-8"):
    if line.startswith("hex="): seed_hex = line.strip()[4:]
prefix = seed_hex[:48]
pattern = " ".join(prefix[i:i+2] for i in range(0, len(prefix), 2))
TARGET = int(sys.argv[1]) if len(sys.argv) > 1 else "TikTok"

JS = r"""
var SEED_LEN = 176;
var pattern = "%s";
var fullHex = "%s";
var OFF = 0x11c580;
var signing = {};   // threadId -> bool
var META = Process.findModuleByName("libmetasec_ov.so");
function inMeta(a){ return META && a.compare(META.base)>=0 && a.compare(META.base.add(META.size))<0; }

// hook dispatcher: danh dau thread dang ky (cmd >> 24 >= 4)
if(META){
    Interceptor.attach(META.base.add(OFF), {
        onEnter:function(a){
            this.cat = a[2].toInt32() >>> 24;
            if(this.cat>=4){ signing[this.threadId]=true; }
        },
        onLeave:function(r){ if(this.cat>=4){ signing[this.threadId]=false; } }
    });
    send("hook dispatcher @ libmetasec+0x"+OFF.toString(16));
}

// scan async (khong block load)
setTimeout(function(){
    var seedAddrs = [];
    var ranges = Process.enumerateRanges('rw-');
    send("scan "+ranges.length+" rw- ranges...");
    for(var r=0;r<ranges.length;r++){
        try{
            var res = Memory.scanSync(ranges[r].base, ranges[r].size, pattern);
            for(var i=0;i<res.length;i++){
                // xac nhan full 176
                var ok=true;
                var bytes=new Uint8Array(res[i].address.readByteArray(SEED_LEN));
                for(var j=0;j<SEED_LEN;j++){ if(bytes[j]!==parseInt(fullHex.substr(j*2,2),16)){ ok=false; break; } }
                if(ok){ seedAddrs.push(res[i].address); }
            }
        }catch(e){}
        if(seedAddrs.length>=4) break;
    }
    send("seed tim thay o "+seedAddrs.length+" dia chi: "+seedAddrs.join(", "));
    if(seedAddrs.length===0){ send("KHONG con seed trong RAM (co the da free)"); return; }

    // MemoryAccessMonitor tren tung trang chua seed
    var watch = seedAddrs.map(function(ad){ return { base: ad, size: SEED_LEN }; });
    var hitCount=0;
    MemoryAccessMonitor.enable(watch, {
        onAccess: function(d){
            hitCount++;
            var from = d.from;
            var inM = inMeta(from);
            var sgn = !!signing[Process.getCurrentThreadId ? Process.getCurrentThreadId() : 0];
            var loc = inM ? ("libmetasec+0x"+from.sub(META.base).toString(16)) : (""+from);
            var mod = Process.findModuleByAddress(from);
            send((inM?">>> SEED READ BY LIBMETASEC":"    seed access")+
                 " op="+d.operation+" from="+loc+
                 (mod&&!inM?(" ("+mod.name+")"):"")+
                 " signing="+sgn+" addr="+d.address);
            // re-arm de bat tiep
            try{ MemoryAccessMonitor.enable(watch, this); }catch(e){}
        }
    });
    send("MemoryAccessMonitor DANG theo doi "+watch.length+" vung seed. Nudge app de ky...");
}, 300);
""" % (pattern, seed_hex)

def on_message(m, d):
    if m.get("type") == "send": print(m["payload"])
    elif m.get("type") == "error": print("[ERR]", m.get("stack"))

def main():
    dev = frida.get_usb_device(timeout=10)
    session = dev.attach(TARGET)
    sc = session.create_script(JS); sc.on("message", on_message); sc.load()
    print("[*] theo doi 30s (nudge app song song)...")
    time.sleep(30)
    try: session.detach()
    except: pass

if __name__ == "__main__":
    main()

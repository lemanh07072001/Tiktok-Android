#!/usr/bin/env python3
# Plan A: extract TLS1.3/QUIC traffic secrets from BoringSSL via keylog callback.
# Hook libttboringssl SSL_new(ctx) -> SSL_CTX_set_keylog_callback(ctx, cb).
# cb(ssl, line) receives NSS-keylog-format lines (CLIENT_TRAFFIC_SECRET_0 ...).
# Those lines let an offline decoder derive QUIC 1-RTT keys and decrypt the wire.
import frida, sys, os, time
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except: pass

PKG = "com.zhiliaoapp.musically"
DUR = int(os.environ.get("DUR", "40"))
OUT = os.environ.get("OUT", "ground-truth/getseed_wire/keylog.txt")
LIB = "libttboringssl.so"

JS = r"""
const LIB='libttboringssl.so';
let installed=false;
let CB=null;                 // keep NativeCallback alive (no GC)
const seenCtx={};
function install(){
  if(installed) return true;
  const m=Process.findModuleByName(LIB);
  if(!m) return false;
  // resolve exports by name, fall back to known offsets
  function ex(name,off){
    let p=null;
    try{ p=m.findExportByName(name); }catch(e){ p=null; }
    if(!p||p.isNull()) p=m.base.add(off);
    return p;
  }
  const pSSL_new = ex('SSL_new', 0x32dc4);
  const pSetKL   = ex('SSL_CTX_set_keylog_callback', 0x35890);
  const setKL = new NativeFunction(pSetKL,'void',['pointer','pointer']);
  // void cb(const SSL* ssl, const char* line)
  CB = new NativeCallback(function(ssl,line){
    try{ const s=line.readCString(); if(s) send({t:'kl',line:s}); }catch(e){}
  },'void',['pointer','pointer']);
  Interceptor.attach(pSSL_new,{onEnter(a){
    try{
      const ctx=a[0];
      if(ctx.isNull()) return;
      const key=ctx.toString();
      if(seenCtx[key]) return;
      seenCtx[key]=1;
      setKL(ctx, CB);
      send({t:'info',msg:'keylog armed on ctx '+key});
    }catch(e){ send({t:'info',msg:'onEnter err '+e}); }
  }});
  installed=true;
  send({t:'info',msg:'hooked '+LIB+' SSL_new@'+pSSL_new+' setKL@'+pSetKL});
  return true;
}
if(!install()){
  const dl=Module.findGlobalExportByName('android_dlopen_ext')||Module.findGlobalExportByName('dlopen');
  Interceptor.attach(dl,{onEnter(a){try{this.p=a[0].readCString();}catch(e){this.p=null;}},
    onLeave(){ if(this.p && this.p.indexOf(LIB)>=0) install(); }});
  send({t:'info',msg:'deferred: waiting for '+LIB+' via dlopen'});
}
"""

os.makedirs(os.path.dirname(OUT), exist_ok=True)
dev = frida.get_usb_device(timeout=10)
print("[*] spawn", PKG, "DUR=%ds" % DUR, "OUT=%s" % OUT, flush=True)
pid = dev.spawn([PKG]); s = dev.attach(pid); sc = s.create_script(JS)
lines = []
def om(m, d):
    if m.get("type") == "error":
        print("[ERR]", m.get("description")); return
    p = m.get("payload") or {}
    if p.get("t") == "info":
        print("[*]", p["msg"], flush=True)
    elif p.get("t") == "kl":
        ln = p["line"]; lines.append(ln)
        # print only the tag (secret redacted) to console
        tag = ln.split(" ")[0] if ln else "?"
        print("[KL]", tag, flush=True)
sc.on("message", om); sc.load(); dev.resume(pid)
t0 = time.time()
while time.time() - t0 < DUR: time.sleep(0.5)
try: s.detach()
except: pass
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + ("\n" if lines else ""))
# summary by tag
from collections import Counter
c = Counter(l.split(" ")[0] for l in lines if l)
print("\n=== keylog summary (%d lines) -> %s ===" % (len(lines), OUT))
for tag, n in sorted(c.items()): print("  %-32s x%d" % (tag, n))

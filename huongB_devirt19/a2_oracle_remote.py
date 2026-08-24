#!/usr/bin/env python3
# A2 ORACLE (remote): phone ký X-Argus GENUINE (có #18/#19 baked-in) qua msnkd:47119.
#   Hook libmetasec_ov.so + MS_SIGN_OFF (45.5.4/.7.3 = 0x9ecc0) : sign(url, hdr) -> "X-Argus\r\n...".
#   HTTP :PORT  POST /sign {url, hdr} -> {"X-Argus","X-Gorgon","X-Khronos","X-Ladon"}.
#   client dùng: METASEC_ORACLE=http://127.0.0.1:8795 node ... (src/sign.mjs tự route).
#   Chạy: python a2_oracle_remote.py [PORT]   (cần msnkd chạy :47119 + app logged-in)
import sys, os, json, time, frida
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

PKG = "com.zhiliaoapp.musically"
HOST = os.environ.get("FRIDA_HOST", "127.0.0.1:47119")
SIGN_OFF = os.environ.get("MS_SIGN_OFF", "0x9ecc0")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8795
JS = r"""
const LIB='libmetasec_ov.so'; const SIGN_OFF=%s;
let sign=null, base=null;
function init(){ const m=Process.findModuleByName(LIB); if(!m) return false;
  base=m.base; sign=new NativeFunction(m.base.add(SIGN_OFF),'pointer',['pointer','pointer']); return true; }
rpc.exports={ ready(){ return !!sign || init(); },
  sign(url,hdr){ if(!sign && !init()) throw new Error('libmetasec chua nap');
    const u=Memory.allocUtf8String(url), h=Memory.allocUtf8String(hdr);
    const r=sign(u,h); return r.isNull()?null:r.readUtf8String(); } };
""" % SIGN_OFF

dev = frida.get_device_manager().add_remote_device(HOST)
# attach to the MAIN process (the one with libmetasec loaded)
procs = [p for p in dev.enumerate_processes() if PKG in p.name or "tiktok" in p.name.lower() or "music" in p.name.lower()]
sess = None
for p in procs:
    try:
        s = dev.attach(p.pid); sc = s.create_script(JS); sc.load()
        if sc.exports_sync.ready():
            sess, script = s, sc
            print("[*] attached main pid=%d (%s) libmetasec ready" % (p.pid, p.name), flush=True); break
        s.detach()
    except Exception as e:
        print("[skip] pid", p.pid, e)
if not sess:
    print("[!] no process with libmetasec loaded — mở app + login + lướt feed rồi chạy lại"); sys.exit(1)

def parse(out):
    res = {}
    if not out: return res
    lines = out.replace("\r\n", "\n").split("\n"); i = 0
    while i < len(lines) - 1:
        k = lines[i].strip()
        if k.lower().startswith("x-"): res[k] = lines[i+1].strip(); i += 2
        else: i += 1
    return res

# ---- self-test on startup: sign a sample device_register request ----
if os.environ.get("SELFTEST", "1") == "1":
    turl = "https://api-boot.tiktokv.com/service/2/device_register/?device_platform=android&aid=1233&version_code=2024505040"
    thdr = "x-ss-stub\r\n01205F31B47EC9C72AB1A5555960AA63\r\ncontent-type\r\napplication/json; charset=utf-8\r\nx-ss-req-ticket\r\n%d\r\nsdk-version\r\n2\r\npassport-sdk-version\r\n1\r\nuser-agent\r\ncom.zhiliaoapp.musically/2024505040" % int(time.time()*1000)
    try:
        out = script.exports_sync.sign(turl, thdr); r = parse(out)
        xa = r.get("X-Argus", "")
        print("[SELFTEST] X-Argus len=%d (offline thin=324; genuine≈700+) X-Gorgon=%s X-Khronos=%s" % (len(xa), r.get("X-Gorgon","?")[:20], r.get("X-Khronos","?")))
        print("[SELFTEST] %s" % ("GENUINE (phone-grade, has #18/#19 baked in)" if len(xa) > 500 else "SHORT — check app logged-in/foreground"))
    except Exception as e:
        print("[SELFTEST] err", e)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        try:
            n = int(self.headers.get("content-length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            out = script.exports_sync.sign(body["url"], body.get("hdr") or body.get("headerBlock", ""))
            data = json.dumps(parse(out)).encode()
            self.send_response(200); self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
        except Exception as e:
            msg = json.dumps({"error": str(e)}).encode()
            self.send_response(500); self.send_header("content-length", str(len(msg))); self.end_headers(); self.wfile.write(msg)
            print("[ERR]", e)

print("[*] A2 ORACLE http://127.0.0.1:%d/sign  (client: METASEC_ORACLE=http://127.0.0.1:%d)" % (PORT, PORT), flush=True)
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()

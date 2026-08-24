# ROOT-CAUSE decisive test: expose SESSION_PSK by dumping EVERY SM3(0xa0748) message during ONE genuine
#   device_register sign, then scan for the inner-report-key derivation input SM3(PSK||rb||PSK)[:32]
#   -> a message whose first 32 bytes == last 32 bytes (PSK is the repeated half; rb sits in the middle).
#   If found: SESSION_PSK is captured -> #18/#19/#20/report-encrypt all become offline-reproducible
#   (per-session capture, NOT per-request). test-before-conclude: dump ALL msgs, verify palindrome empirically.
import sys, os, time, frida
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
HOST=os.environ.get("FRIDA_HOST","127.0.0.1:47119")
SIGN_OFF=os.environ.get("MS_SIGN_OFF","0x9ecc0")
PID=int(os.environ.get("MS_PID","15803"))

JS=r"""
const LIB='libmetasec_ov.so'; const SIGN_OFF=%s; const SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
let mm=Process.findModuleByName(LIB); let base=mm?mm.base:null; let sign=null;
function initSign(){ if(!mm) return false; sign=new NativeFunction(base.add(SIGN_OFF),'pointer',['pointer','pointer']); return true; }
function hx(u){ let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
send({t:'info',msg: mm?('base='+base):'no metasec'});
let CAP=false;
const chain={};
if(mm){ Interceptor.attach(base.add(SM3),{ onEnter(){
  if(!CAP) return;
  const tid=this.threadId; let st, inp;
  try{ st=hx(new Uint8Array(this.context.x0.add(8).readByteArray(32)));
       inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
  if(st===IV_LE) chain[tid]=Array.from(inp);
  else if(chain[tid]) { for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
  else return;
  const a=chain[tid], L=a.length; if(L<9) return;
  let bitlen=0; for(let i=L-8;i<L;i++) bitlen=bitlen*256+a[i];   // SM3 big-endian length
  const mlen=bitlen/8;
  if(!(mlen>0 && mlen<L) || a[mlen]!==0x80) return;              // not a complete padded message yet
  const msg=a.slice(0,mlen);
  delete chain[tid];
  send({t:'msg', len:mlen, hex:hx(msg)});
}});}
rpc.exports={ ready(){ return !!sign||initSign(); },
  cap(on){ CAP=!!on; },
  sign(url,hdr){ if(!sign&&!initSign()) throw new Error('no metasec');
    const u=Memory.allocUtf8String(url), h=Memory.allocUtf8String(hdr);
    const r=sign(u,h); return r.isNull()?null:r.readUtf8String(); } };
""" % SIGN_OFF

dev=frida.get_device_manager().add_remote_device(HOST); MSGS=[]
s=dev.attach(PID); sc=s.create_script(JS)
sc.on("message", lambda m,d: (MSGS.append(m["payload"]) if m.get("type")=="send" else print("[frida]",m)))
sc.load()
if not sc.exports_sync.ready(): print("[!] not ready"); sys.exit(1)
print("[*] attached pid=%d"%PID, flush=True)

TURL="https://api-boot.tiktokv.com/service/2/device_register/?device_platform=android&aid=1233&version_code=2024505040"
THDR=("x-ss-stub\r\n01205F31B47EC9C72AB1A5555960AA63\r\ncontent-type\r\napplication/json; charset=utf-8\r\n"
  "x-ss-req-ticket\r\n1756000000000\r\nsdk-version\r\n2\r\npassport-sdk-version\r\n1\r\n"
  "user-agent\r\ncom.zhiliaoapp.musically/2024505040")
sc.exports_sync.cap(True)
out=sc.exports_sync.sign(TURL, THDR)
time.sleep(0.6); sc.exports_sync.cap(False)

msgs=[m for m in MSGS if m.get("t")=="msg"]
# dedupe by hex, keep count
from collections import Counter
cnt=Counter(m["hex"] for m in msgs)
uniq=sorted(cnt.items(), key=lambda kv:(len(kv[0]), kv[0]))
print("[*] total SM3 msgs=%d  unique=%d"%(len(msgs), len(uniq)), flush=True)

def ascii_prev(b, n=48):
    return "".join(chr(x) if 32<=x<127 else "." for x in b[:n])

# scan for PSK palindrome: first 32 == last 32 bytes (PSK||rb||PSK)
print("\n===== PSK PALINDROME SCAN (msg[:32]==msg[-32:]) =====")
found=[]
for hx_,c in uniq:
    b=bytes.fromhex(hx_); L=len(b)
    if 64 < L <= 100 and b[:32]==b[-32:]:
        psk=b[:32]; rb=b[32:L-32]
        print("  >>> HIT len=%d count=%d  SESSION_PSK=%s  rb(%dB)=%s"%(L,c,psk.hex(),len(rb),rb.hex()))
        found.append((psk,rb,L))

# also: any msg whose halves match with 32<=half (generic A||A, no middle)
for hx_,c in uniq:
    b=bytes.fromhex(hx_); L=len(b)
    if L>=64 and L%2==0 and b[:L//2]==b[L//2:] and L<=128:
        print("  [A||A] len=%d count=%d half=%s"%(L,c,b[:L//2].hex()))

print("\n===== ALL UNIQUE SM3 MESSAGES (len, count) =====")
for hx_,c in uniq:
    b=bytes.fromhex(hx_); L=len(b)
    tag=""
    if b.rstrip(b'\x00')[-1:]==b'0' and b'device_platform=' in b: tag=" <#19?>"
    if L<=100: print("  len=%3d x%d%s  hex=%s"%(L,c,tag,hx_))
    else:      print("  len=%3d x%d%s  ascii=%s | tailhex=..%s"%(L,c,tag,ascii_prev(b), hx_[-32:]))

print("\n===== VERDICT =====")
if found:
    print("SESSION_PSK EXPOSED via SM3(PSK||rb||PSK) input. Root cause CLOSED: one runtime secret gates all 4 rows.")
    print("  => offline-genuine = per-SESSION PSK capture (cheap), NOT per-request devirt.")
else:
    print("No PSK||rb||PSK palindrome among SM3 inputs. Inner key derivation may not route through 0xa0748,")
    print("  or uses different concat/hash. Next: dump inputs of MD5(0x15b594) + look for 32B key material.")

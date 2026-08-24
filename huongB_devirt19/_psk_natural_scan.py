# FOLLOW-UP: the forced RPC sign() gave only 3 SM3 calls + LICENSE_PSK fallback -> likely THIN report.
#  (1) confirm thin vs genuine by X-Argus length of the forced sign.
#  (2) capture SM3(0xa0748) inputs during NATURAL app traffic (fully provisioned) and scan for a
#      PSK||rb||PSK palindrome whose PSK != LICENSE_PSK  => that would be the runtime SESSION_PSK.
import sys, os, time, subprocess, frida
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
HOST=os.environ.get("FRIDA_HOST","127.0.0.1:47119")
SIGN_OFF=os.environ.get("MS_SIGN_OFF","0x9ecc0")
PID=int(os.environ.get("MS_PID","15803"))
LICENSE_PSK='c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163'
RUN=int(os.environ.get("RUN_SEC","28"))

JS=r"""
const LIB='libmetasec_ov.so'; const SIGN_OFF=%s; const SM3=0xa0748;
const IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0';
let mm=Process.findModuleByName(LIB); let base=mm?mm.base:null; let sign=null;
function initSign(){ if(!mm) return false; sign=new NativeFunction(base.add(SIGN_OFF),'pointer',['pointer','pointer']); return true; }
function hx(u){ let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
send({t:'info',msg: mm?('base='+base):'no metasec'});
let CAP=false; const chain={};
if(mm){ Interceptor.attach(base.add(SM3),{ onEnter(){
  if(!CAP) return;
  const tid=this.threadId; let st, inp;
  try{ st=hx(new Uint8Array(this.context.x0.add(8).readByteArray(32)));
       inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
  if(st===IV_LE) chain[tid]=Array.from(inp);
  else if(chain[tid]) { for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
  else return;
  const a=chain[tid], L=a.length; if(L<9) return;
  let bitlen=0; for(let i=L-8;i<L;i++) bitlen=bitlen*256+a[i];
  const mlen=bitlen/8;
  if(!(mlen>0 && mlen<L) || a[mlen]!==0x80) return;
  delete chain[tid];
  send({t:'msg', len:mlen, hex:hx(a.slice(0,mlen))});
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

def xargus_len(out):
    if not out: return 0
    parts=out.replace("\r\n","\n").split("\n")
    for i,k in enumerate(parts[:-1]):
        if k.strip().lower()=="x-argus": return len(parts[i+1].strip())
    return 0

def scan(label, msgs):
    from collections import Counter
    cnt=Counter(m["hex"] for m in msgs)
    uniq=sorted(cnt.items(), key=lambda kv:(len(kv[0]), kv[0]))
    print("\n===== %s : total=%d unique=%d ====="%(label, len(msgs), len(uniq)))
    psks=set()
    for hx_,c in uniq:
        b=bytes.fromhex(hx_); L=len(b)
        if 64 < L <= 100 and b[:32]==b[-32:]:
            psk=b[:32].hex(); rb=b[32:L-32].hex()
            tag="LICENSE_PSK" if psk==LICENSE_PSK else "*** NON-LICENSE (SESSION_PSK?) ***"
            print("  PALINDROME len=%d x%d  psk=%s rb=%s  [%s]"%(L,c,psk,rb,tag))
            psks.add(psk)
    for hx_,c in uniq:
        b=bytes.fromhex(hx_); L=len(b)
        pv="".join(chr(x) if 32<=x<127 else "." for x in b[:40])
        if L<=90: print("   len=%3d x%d hex=%s"%(L,c,hx_))
        else:     print("   len=%3d x%d ascii=%s"%(L,c,pv))
    return psks

# ---- Phase 1: forced sign, check thin/genuine ----
TURL="https://api-boot.tiktokv.com/service/2/device_register/?device_platform=android&aid=1233&version_code=2024505040"
THDR=("x-ss-stub\r\n01205F31B47EC9C72AB1A5555960AA63\r\ncontent-type\r\napplication/json; charset=utf-8\r\n"
  "x-ss-req-ticket\r\n1756000000000\r\nsdk-version\r\n2\r\npassport-sdk-version\r\n1\r\n"
  "user-agent\r\ncom.zhiliaoapp.musically/2024505040")
sc.exports_sync.cap(True)
base_n=len(MSGS); out=sc.exports_sync.sign(TURL, THDR); time.sleep(0.5)
xl=xargus_len(out)
print("[*] FORCED sign X-Argus len=%d  (thin~320-330 / genuine 500-700+)"%xl, flush=True)
scan("FORCED sign SM3", [m for m in MSGS[base_n:] if m.get("t")=="msg"])

# ---- Phase 2: natural traffic ----
try:
    subprocess.run(['adb','shell','am','start','-n','com.zhiliaoapp.musically/com.ss.android.ugc.aweme.main.MainActivity'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
except Exception as e: print("[!] am start:",e)
print("[*] observing %ds of NATURAL traffic (fully provisioned signs)..."%RUN, flush=True)
base_n=len(MSGS); time.sleep(RUN); sc.exports_sync.cap(False)
nat=scan("NATURAL traffic SM3", [m for m in MSGS[base_n:] if m.get("t")=="msg"])

print("\n===== VERDICT =====")
nonlic=[p for p in nat if p!=LICENSE_PSK]
if nonlic:
    for p in nonlic: print("SESSION_PSK (runtime, != LICENSE) EXPOSED:", p)
    print("  => root cause = this runtime PSK. Capture it per-session -> offline-genuine.")
elif nat:
    print("Only LICENSE_PSK appears in PSK||rb||PSK even under natural traffic.")
    print("  => inner key uses LICENSE_PSK (build const), NOT a separate session secret. Big implication:")
    print("     the PSK half of the key is ALREADY KNOWN offline; the gate is elsewhere (provisioning flag/#20).")
else:
    print("No palindrome under natural traffic (signs may not have fired). Increase RUN_SEC / interact more.")

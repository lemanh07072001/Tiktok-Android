# slot16 DETERMINISM probe (test-before-conclude): is #19's slot16 a per-request nonce/ratchet
#   or deterministic from (PSK, query)? Decides if offline-genuine is cheap (forge slot16) or needs Track A.
#   Method: force the SAME device_register sign N times (FIXED input incl. x-ss-req-ticket) via base+SIGN_OFF,
#   hook SM3 0xa0748 to reconstruct #19 msg = query||slot16(16)||0x30, record slot16 per call. Then vary input.
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
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
function asc(u,a,b){ let s=''; for(let i=a;i<b;i++) s+=String.fromCharCode(u[i]); return s; }
send({t:'info',msg: mm? ('metasec base='+base):'metasec NOT loaded'});
if(mm){
  const chain={};
  Interceptor.attach(base.add(SM3),{ onEnter(){
    const tid=this.threadId; let st,inp;
    try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=new Uint8Array(this.context.x1.readByteArray(64)); }catch(e){ return; }
    if(st===IV_LE) chain[tid]=Array.from(inp);
    else if(chain[tid]){ for(let i=0;i<64;i++) chain[tid].push(inp[i]); }
    else return;
    const a=chain[tid], L=a.length; if(L<9) return;
    let bitlen=0; for(let i=L-8;i<L;i++) bitlen=bitlen*256+a[i];
    const mlen=bitlen/8;
    if(!(mlen>16&&mlen<L)||a[mlen]!==0x80) return;        // message not complete yet
    if(a[mlen-1]!==0x30||mlen<64){ delete chain[tid]; return; }
    const full=asc(a,0,mlen-17);                           // query part (before slot16+0x30)
    if(full.indexOf('device_platform=')<0){ delete chain[tid]; return; }  // #19 signature
    let slot=''; for(let i=mlen-17;i<mlen-1;i++) slot+=('0'+a[i].toString(16)).slice(-2);
    send({t:'obs', slot16:slot, qlen:full.length, qhash: full.length+':'+full.slice(0,24)+'|'+full.slice(-24)});
    delete chain[tid];
  }});
}
rpc.exports={ ready(){ return !!sign||initSign(); },
  sign(url,hdr){ if(!sign&&!initSign()) throw new Error('no metasec');
    const u=Memory.allocUtf8String(url), h=Memory.allocUtf8String(hdr);
    const r=sign(u,h); return r.isNull()?null:r.readUtf8String(); } };
send({t:'info',msg:'armed'});
""" % SIGN_OFF

dev=frida.get_device_manager().add_remote_device(HOST)
MSGS=[]
try:
    s=dev.attach(PID); sc=s.create_script(JS)
    def on(m,d):
        if m.get("type")=="send": MSGS.append(m["payload"])
        else: print("[frida]",m)
    sc.on("message",on); sc.load()
    if not sc.exports_sync.ready(): print("[!] libmetasec not ready"); sys.exit(1)
    print("[*] attached pid=%d, libmetasec ready"%PID, flush=True)
except Exception as e:
    print("[!] attach failed:", e); sys.exit(1)

def parse_xargus(out):
    if not out: return ""
    parts=out.replace("\r\n","\n").split("\n")
    for i,k in enumerate(parts[:-1]):
        if k.strip().lower()=="x-argus": return parts[i+1].strip()
    return ""

TURL="https://api-boot.tiktokv.com/service/2/device_register/?device_platform=android&aid=1233&version_code=2024505040"
def hdr(ticket): return ("x-ss-stub\r\n01205F31B47EC9C72AB1A5555960AA63\r\ncontent-type\r\napplication/json; charset=utf-8\r\n"
    "x-ss-req-ticket\r\n%d\r\nsdk-version\r\n2\r\npassport-sdk-version\r\n1\r\n"
    "user-agent\r\ncom.zhiliaoapp.musically/2024505040" % ticket)

def run_batch(label, tickets):
    print("\n===== BATCH %s ====="%label, flush=True)
    rows=[]
    for tk in tickets:
        base_n=len(MSGS)
        try: out=script_sign(TURL, hdr(tk))
        except Exception as e: print("  sign err", e); continue
        xa=parse_xargus(out)
        time.sleep(0.25)
        obs=[m for m in MSGS[base_n:] if m.get("t")=="obs"]
        slot=obs[-1]["slot16"] if obs else "(none)"
        qh = obs[-1]["qhash"] if obs else ""
        rows.append((tk, slot, len(xa), qh))
        print("  ticket=%d  xargus_len=%d  slot16=%s"%(tk, len(xa), slot), flush=True)
    return rows

script_sign=sc.exports_sync.sign

# BATCH A: IDENTICAL input (same ticket) x10  -> any slot16 change = per-call ratchet/nonce
FIXED=1756000000000
rowsA=run_batch("A: IDENTICAL input x10 (fixed ticket=%d)"%FIXED, [FIXED]*10)
# BATCH B: VARYING ticket x6 -> does input change slot16?
import time as _t
rowsB=run_batch("B: VARYING ticket x6", [int(_t.time()*1000)+i for i in range(6)])

def analyze(label, rows):
    slots=[r[1] for r in rows if r[1]!="(none)"]
    uniq=sorted(set(slots))
    print("\n[ANALYZE %s] captured=%d  distinct_slot16=%d"%(label, len(slots), len(uniq)))
    for u in uniq[:12]: print("   ", u)
    # zero-byte ratio of first captured
    if slots:
        b=bytes.fromhex(slots[0]); zr=sum(1 for x in b if x==0)
        print("   slot16[0] zero-bytes=%d/16"%zr)
    return uniq

uA=analyze("A(identical)", rowsA)
uB=analyze("B(varying)", rowsB)

print("\n===== VERDICT =====")
if len(uA)<=1:
    print("slot16 STABLE under identical input  -> deterministic from (PSK+query state); NOT a per-call random nonce.")
    print("  => offline-genuine needs the provisioned PSK state/function (Track A/B territory), NOT free-forgeable.")
else:
    print("slot16 CHANGES under identical input (%d distinct/10) -> per-call ratchet or nonce component."%len(uA))
    print("  => if server cannot re-derive it, slot16 is a client nonce we may forge offline (cheap genuine!).")
    # ratchet check: do distinct values differ only in low bytes (counter) or wholesale (random)?
    if len(uA)>=2:
        xs=[bytes.fromhex(x) for x in [rowsA[i][1] for i in range(len(rowsA)) if rowsA[i][1]!="(none)"]]
        diffpos=set()
        for i in range(1,len(xs)):
            for j in range(16):
                if xs[i][j]!=xs[0][j]: diffpos.add(j)
        print("  byte positions that vary across identical-input calls:", sorted(diffpos))

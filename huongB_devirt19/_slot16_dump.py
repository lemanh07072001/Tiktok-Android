# SM3 raw-block DUMP (diagnose why slot16 reconstruction got 0). Hook 0xa0748, on each onEnter emit
#   {st_in(32B), inp(64B)}; force ONE device_register sign; reconstruct hashes in Python (split on IV).
import sys, os, time, frida
try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass
HOST=os.environ.get("FRIDA_HOST","127.0.0.1:47119"); SIGN_OFF=os.environ.get("MS_SIGN_OFF","0x9ecc0")
PID=int(os.environ.get("MS_PID","15803"))
IV_LE='6f168073b9b21449d742241700068adabc306fa9aa3831164dee8de34e0efbb0'

JS=r"""
const LIB='libmetasec_ov.so'; const SIGN_OFF=%s; const SM3=0xa0748;
let mm=Process.findModuleByName(LIB); let base=mm?mm.base:null; let sign=null;
function initSign(){ if(!mm) return false; sign=new NativeFunction(base.add(SIGN_OFF),'pointer',['pointer','pointer']); return true; }
function hx(ab){ const u=new Uint8Array(ab); let s=''; for(let i=0;i<u.length;i++) s+=('0'+u[i].toString(16)).slice(-2); return s; }
send({t:'info',msg: mm?('base='+base):'no metasec'});
let CAP=false;
if(mm){ Interceptor.attach(base.add(SM3),{ onEnter(){
  if(!CAP) return; let st,inp;
  try{ st=hx(this.context.x0.add(8).readByteArray(32)); inp=hx(this.context.x1.readByteArray(64)); }catch(e){ return; }
  send({t:'blk', tid:this.threadId, st:st, inp:inp});
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
time.sleep(0.4); sc.exports_sync.cap(False)
xa=""
for i,k in enumerate(out.replace("\r\n","\n").split("\n")[:-1]):
    if k.strip().lower()=="x-argus": xa=out.replace("\r\n","\n").split("\n")[i+1].strip()
blks=[m for m in MSGS if m.get("t")=="blk"]
print("[*] X-Argus len=%d  SM3 onEnter blocks=%d"%(len(xa), len(blks)), flush=True)

# group into hashes: a new hash begins where st==IV_LE
hashes=[]; cur=None
for b in blks:
    if b["st"]==IV_LE:
        if cur: hashes.append(cur)
        cur=[b["inp"]]
    elif cur is not None:
        cur.append(b["inp"])
if cur: hashes.append(cur)
print("[*] reconstructed %d hash(es):"%len(hashes))
for hi,h in enumerate(hashes):
    raw=bytes.fromhex("".join(h))            # padded message (blocks*64)
    L=len(raw)
    bitlen=int.from_bytes(raw[-8:],"big"); mlen=bitlen//8
    ok = 0<mlen<L and raw[mlen]==0x80
    msg=raw[:mlen] if ok else b""
    txt="".join(chr(x) if 32<=x<127 else "." for x in msg[:80])
    tail="".join(chr(x) if 32<=x<127 else "." for x in msg[-24:]) if ok else ""
    hasdp = b"device_platform=" in msg
    print("  #%d blocks=%d padL=%d mlen=%s lastbyte=%s dp=%s"%(hi,len(h),L, mlen if ok else "?", ("%02x"%msg[-1]) if ok else "?", hasdp))
    print("      head: %s"%txt)
    if ok: print("      tail: ...%s"%tail)
    if ok and hasdp and msg[-1]==0x30:
        slot=msg[mlen-17:mlen-1].hex()
        print("      >>> #19 CANDIDATE  slot16=%s"%slot)

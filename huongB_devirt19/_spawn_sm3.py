import frida,sys,time,json,collections
import sm3_hash19 as S; sm3=S.sm3
SK="c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163"
PKG="com.zhiliaoapp.musically"
DUR=int(sys.argv[1]) if len(sys.argv)>1 else 45
recs=[]
def on(m,d):
    if m['type']!='send': return
    p=m['payload']; k=p.get('k')
    if k in ('S','L'): recs.append(p)
    elif k in ('BASE','READY'): print("  ",k)
    else: print("  ",p)
dev=frida.get_usb_device()
print("spawning",PKG,"(login persists on /data — KHÔNG re-register)")
pid=dev.spawn([PKG])
sess=dev.attach(pid)
sc=sess.create_script(open("_sm3net.js").read())
sc.on('message',on); sc.load()
dev.resume(pid)
print("resumed pid",pid,"— chờ startup + swipe feed...")
import subprocess,os
env=dict(os.environ); env["PATH"]=os.path.expanduser("~/Library/Android/sdk/platform-tools")+":"+env.get("PATH","")
def swipe():
    for i in range(DUR//2):
        subprocess.run(["adb","shell","input","swipe","540","1600","540","300","100"],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(1.8)
import threading; threading.Thread(target=swipe,daemon=True).start()
time.sleep(DUR)
# analyze
json.dump(recs,open("_spawn_sm3_out.json","w"),indent=1)   # DUMP TRƯỚC (an toàn)
S_recs=[r for r in recs if r['k']=='S']; L_recs=[r for r in recs if r['k']=='L']
print("\n=== SHORT=%d LONG=%d (saved) ==="%(len(S_recs),len(L_recs)))
prod={}
seen=set()
print("\n--- SHORT 68B SIGN_KEY producer (nonce → SM3[:16]) ---")
for r in S_recs:
    if r['len']==68 and r['hex'].startswith(SK[:32]):
        nonce=r['hex'][64:72]; out=sm3(bytes.fromhex(r['hex'])).hex()[:32]
        if nonce not in seen: seen.add(nonce); prod[out]=nonce; print("  nonce=%s → %s"%(nonce,out))
from collections import Counter
print("  SHORT len dist:", dict(Counter(r['len'] for r in S_recs)))
print("\n--- LONG kết 0x30 (#19 slot16) ---")
slots=set()
for r in L_recs:
    if r['last']==0x30:
        sl=r['tail'][-34:-2]; slots.add(sl); print("  slot16=%s head=%s"%(sl,r['head'][:40]))
print("  LONG last-byte dist:", dict(Counter(r['last'] for r in L_recs)))
print("\n--- ✅ VERIFY slot16 = SM3(SK‖nonce‖SK)[:16]? ---")
hit=False
for sl in slots:
    if sl in prod: print("  ✅✅✅ slot16=%s = SM3(SK‖%s‖SK)  ← CÔNG THỨC ĐÚNG"%(sl,prod[sl])); hit=True
if not hit:
    print("  producer nonces:",list(prod.values())[:8])
    print("  producer outs:",list(prod.keys())[:6])
    print("  slot16 (#19):",list(slots)[:8])

import frida,sys,time,json
PID=int(sys.argv[1]) if len(sys.argv)>1 else 21946
DUR=int(sys.argv[2]) if len(sys.argv)>2 else 40
slot16=[]; maps=[]; other=[]
def on(m,d):
    if m['type']!='send': return
    p=m['payload']; k=p.get('k')
    if k=='UNHEX':
        if p.get('SLOT16'):
            slot16.append(p); print("★SLOT16 hex=%s lr=%s tid=%s"%(p['hex'],p['lr'],p['tid']))
        else:
            other.append(p)
    elif k=='MAP':
        maps.append(p)
    else:
        print("  ",p)
dev=frida.get_usb_device()
sess=dev.attach(PID)
sc=sess.create_script(open("_slot16caller.js").read())
sc.on('message',on); sc.load()
print("ATTACH pid",PID,"— navigate app to trigger feed signs...")
time.sleep(DUR)
# tổng kết
from collections import Counter
print("\n=== SLOT16 unhex call-sites (lr) ===")
c=Counter((s['lr']) for s in slot16)
for lr,n in c.most_common():
    ex=[s['hex'] for s in slot16 if s['lr']==lr][:3]
    print("  lr=%s  ×%d  vd:%s"%(lr,n,ex))
print("\n=== các độ dài hex khác (non-slot16) theo lr ===")
c2=Counter((o['lr'],o['len']) for o in other)
for (lr,ln),n in c2.most_common(10): print("  lr=%s len=%d ×%d"%(lr,ln,n))
print("\n=== MAP lookups (key→val) mẫu ===")
seen=set()
for m in maps:
    key=m['key']
    if key in seen: continue
    seen.add(key)
    print("  '%s' → '%s' (n=%d)"%(key, str(m['val'])[:48], m['vn']))
    if len(seen)>=25: break
json.dump({'slot16':slot16,'maps':maps[:200],'other':other[:200]},open("_slot16caller_out.json","w"),indent=1)
print("\nsaved _slot16caller_out.json  (slot16 hits=%d, maps=%d)"%(len(slot16),len(maps)))

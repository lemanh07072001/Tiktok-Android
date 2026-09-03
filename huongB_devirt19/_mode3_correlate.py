#!/usr/bin/env python3
# Correlate mode3 CRYPT captures against fresh on-disk store files:
# file bytes == out(hex) -> ENCRYPT path, in = PLAINTEXT (Track C deliverable).
# file bytes == in(hex)  -> DECRYPT path, out = PLAINTEXT.
import json,os,glob,subprocess
ADB="/Users/lemanh/Library/Android/sdk/platform-tools/adb"
OV="/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov"
GT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","cap.noindex","gt_live")
os.makedirs(GT,exist_ok=True)
def prt(b): P=set([9,10,13])|set(range(0x20,0x7f)); return sum(1 for x in b if x in P)/len(b) if b else 0
# pull fresh store files
names=subprocess.run([ADB,"shell","su","0","find",OV,"-maxdepth","1","-name",".ms*"],capture_output=True,text=True).stdout.split()
disk={}
for p in names:
    p=p.strip()
    if not p: continue
    b=subprocess.run([ADB,"exec-out","su","0","cat",p],capture_output=True).stdout
    if b: disk[os.path.basename(p)]=b; open(os.path.join(GT,os.path.basename(p)),"wb").write(b)
print("pulled %d store files"%len(disk))
ev=json.load(open("_mode3_out.json"))
cry=[e for e in ev if e['t']=='CRYPT']
print("CRYPT captures=%d  INIT=%d  KSCH=%d"%(len(cry),sum(e['t']=='INIT' for e in ev),sum(e['t']=='KSCH' for e in ev)))
hits=0
for nm,b in disk.items():
    h=b.hex()
    for c in cry:
        if c.get('out')==h:
            pt=bytes.fromhex(c['in']); hits+=1
            print("\n*** ENCRYPT MATCH %s (%dB) key=%s iv=%s"%(nm,len(b),c.get('key'),c.get('iv')))
            print("    PLAINTEXT pr=%.3f head=%s"%(prt(pt),pt[:64]))
        elif c.get('in')==h:
            pt=bytes.fromhex(c['out']); hits+=1
            print("\n*** DECRYPT MATCH %s (%dB) key=%s iv=%s"%(nm,len(b),c.get('key'),c.get('iv')))
            print("    PLAINTEXT pr=%.3f head=%s"%(prt(pt),pt[:64]))
if not hits:
    print("\nNO direct buffer match. mode3 lengths seen:",sorted(set(c['len'] for c in cry)))
    print("disk lengths:",sorted(len(b) for b in disk.values()))

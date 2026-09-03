#!/usr/bin/env python3
# Diagnostic: for each GT file, the BEST printable-ratio decrypt across ALL
# captured keys x ivs x {CTR,CFB,OFB,CBC,ECB,+pfx16}. If best~0.4 => key absent.
import json,os,glob
from Crypto.Cipher import AES
HERE=os.path.dirname(os.path.abspath(__file__))
GT=os.path.join(HERE,"..","cap.noindex","gt_live"); OUT=os.path.join(HERE,"_grab_out.json")
PRT=set([9,10,13])|set(range(0x20,0x7f))
def pr(b): return (sum(1 for x in b if x in PRT)/len(b)) if b else 0.0
ev=json.load(open(OUT)); keys={}; ivs=set([b"\0"*16])
for e in ev:
    uk=e.get("userKey")
    if uk and len(uk)%2==0:
        try:
            kb=bytes.fromhex(uk)
            if len(kb) in (16,24,32): keys[kb.hex()]=kb
        except: pass
    iv=e.get("iv")
    if iv and len(iv)==32:
        try: ivs.add(bytes.fromhex(iv))
        except: pass
ivl=list(ivs)
def decs(kb,ct,iv):
    o={}
    L=len(ct)
    try:o["CTR"]=AES.new(kb,AES.MODE_CTR,nonce=b"",initial_value=int.from_bytes(iv,"big")).decrypt(ct)
    except:pass
    try:o["CFB"]=AES.new(kb,AES.MODE_CFB,iv=iv,segment_size=128).decrypt(ct)
    except:pass
    try:o["OFB"]=AES.new(kb,AES.MODE_OFB,iv=iv).decrypt(ct)
    except:pass
    if L%16==0:
        try:o["CBC"]=AES.new(kb,AES.MODE_CBC,iv=iv).decrypt(ct)
        except:pass
    return o
for fp in sorted(glob.glob(os.path.join(GT,".ms*"))):
    ct=open(fp,"rb").read(); nm=os.path.basename(fp)[:24]
    best=(0.0,"","",""); 
    for kh,kb in keys.items():
        for iv in ivl:
            for mode,pt in decs(kb,ct,iv).items():
                r=pr(pt)
                if r>best[0]: best=(r,kh[:8],mode,iv.hex()[:8])
        if len(ct)%16==0:
            try:
                pt=AES.new(kb,AES.MODE_ECB).decrypt(ct); r=pr(pt)
                if r>best[0]: best=(r,kh[:8],"ECB","-")
            except:pass
    print("%-26s %4dB  bestPR=%.3f  key=%s %s iv=%s" % (nm,len(ct),best[0],best[1],best[2],best[3]))
print("\n(random-baseline printable ratio ~ 0.34; real plaintext text >0.9, proto/binary ~0.4-0.6)")

#!/usr/bin/env python3
# Offline DIFF: try captured (key,IV,mode) x header-skip on _msdump/*.bin; score protobuf-likeness.
import itertools, os
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEYS = {
 'K1_10dbb0': 'b114249b7bed9d2691d70c60d69f9c4f',
 'K2_159d90': '8252970d959b06db102e17d85c0ec1af',
 'K3'       : 'b8d72ddec05142948bbf2dc81d63759c',
}
IVS = {
 'IV1':'4d207ea37a419f7d622f81c6a2f53594',
 'IV2':'d6c3969582f9ac5313d39c180b54a2bc',
 'IVZ':'00'*16,
}
FILES = ['_msdump/msp_092f.bin','_msdump/msp_589c.bin','_msdump/mss_9b8e.bin']
SKIPS = [0,2,4,6,8,10,16]

def printable_ratio(b):
    if not b: return 0.0
    p=sum(1 for x in b if 9<=x<=13 or 32<=x<=126)
    return p/len(b)

def protobuf_score(b):
    # valid store plaintext starts with a small field tag: field 1..15, wire 0(varint)/2(len)
    if len(b)<2: return 0
    t=b[0]
    good_first = t in (0x08,0x0a,0x10,0x12,0x18,0x1a,0x20,0x22,0x28,0x2a)
    # walk a couple of fields shallowly
    s = 3 if good_first else 0
    s += int(printable_ratio(b[:64])*4)   # ascii-ish payload (device ids etc.)
    # penalise if looks like random (printable<0.35 across whole)
    if printable_ratio(b)<0.30: s-=1
    return s

def dec(mode,key,iv,ct):
    try:
        if mode=='cbc':
            if len(ct)%16: return None
            return AES.new(key,AES.MODE_CBC,iv).decrypt(ct)
        if mode=='ecb':
            if len(ct)%16: return None
            return AES.new(key,AES.MODE_ECB).decrypt(ct)
        if mode=='cfb':
            return AES.new(key,AES.MODE_CFB,iv,segment_size=128).decrypt(ct)
        if mode=='ofb':
            return AES.new(key,AES.MODE_OFB,iv).decrypt(ct)
        if mode=='ctr':
            ctr=Counter.new(128,initial_value=int.from_bytes(iv,'big'))
            return AES.new(key,AES.MODE_CTR,counter=ctr).decrypt(ct)
    except Exception:
        return None

hits=[]
for fp in FILES:
    data=open(fp,'rb').read()
    for skip in SKIPS:
        ct=data[skip:]
        for kn,kh in KEYS.items():
            key=bytes.fromhex(kh)
            for mode in ('cbc','ecb','cfb','ofb','ctr'):
                ivpool = {'--':b''} if mode=='ecb' else IVS
                for ivn,ivh in ivpool.items():
                    iv=bytes.fromhex(ivh) if ivh else b''
                    pt=dec(mode,key,iv,ct)
                    if pt is None: continue
                    sc=protobuf_score(pt)
                    if sc>=4:
                        hits.append((sc,fp,skip,kn,mode,ivn,pt[:32].hex(),printable_ratio(pt)))

hits.sort(reverse=True)
print("=== TOP CANDIDATES (score>=4) ===")
for h in hits[:25]:
    sc,fp,skip,kn,mode,ivn,head,pr=h
    print(f"score={sc} {os.path.basename(fp):14} skip={skip:2} {kn:9} {mode:3} {ivn:3} pr={pr:.2f} head={head}")
if not hits:
    print("NO hit >=4. Dumping best-effort top by printable ratio...")

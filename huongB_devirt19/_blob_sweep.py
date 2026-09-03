#!/usr/bin/env python3
import subprocess, math, itertools, os
KEYS = {
 'A_fixed':   'b114249b7bed9d2691d70c60d69f9c4f',
 'B_v1':      '8252970d959b06db102e17d85c0ec1af',
 'B_v2':      'b8d72ddec05142948bbf2dc81d63759c',
}
BLOBS = ['_msdump/msp_092f.bin','_msdump/msp_589c.bin','_msdump/mss_9b8e.bin']
ZERO='00'*16
def sh(args, data):
    p=subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout
def entropy(b):
    if not b: return 0
    c=[0]*256
    for x in b: c[x]+=1
    n=len(b); e=0
    for v in c:
        if v: p=v/n; e-=p*math.log2(p)
    return e
def printable_ratio(b):
    if not b: return 0
    return sum(1 for x in b if 9<=x<=13 or 32<=x<=126)/len(b)
def score(pt):
    """low entropy + high printable + protobuf markers = plausible plaintext"""
    e=entropy(pt); pr=printable_ratio(pt)
    hexs=pt.hex()
    hits=0
    if b'c02f250f' in pt or 'c02f250f86cc4f198d5706398d292a8b' in hexs: hits+=100  # device-key A
    if b'\x08' in pt[:4] or b'\x0a' in pt[:4]: hits+=1  # protobuf field 1 varint/len
    if b'com.zhiliao' in pt or b'musically' in pt or b'android' in pt: hits+=50
    # structure signal: entropy notably below 7.6 for encrypted-length data
    struct = max(0, 7.9 - e)
    return pr*2 + struct + hits, e, pr, hits
def openssl_dec(mode, key, iv, ct):
    base=['openssl','enc',f'-aes-128-{mode}','-d','-K',key]
    if mode!='ecb': base+=['-iv',iv]
    if mode in ('ecb','cbc'): base+=['-nopad']
    return sh(base, ct)
results=[]
for bpath in BLOBS:
    ct=open(bpath,'rb').read()
    ln=len(ct); aligned = (ln%16==0)
    modes = ['ecb','cbc','ctr','cfb','ofb'] if aligned else ['ctr','cfb','ofb']
    # IV candidates
    for kname,key in KEYS.items():
        ivs = {'zeroIV':ZERO, 'firstblk':ct[:16].hex()}
        for ivname,iv in ivs.items():
            for mode in modes:
                # scheme 1: decrypt whole blob
                pt = openssl_dec(mode,key,iv,ct)
                if pt:
                    s,e,pr,h=score(pt)
                    results.append((s,bpath,kname,mode,ivname,'whole',e,pr,h,pt[:32].hex()))
                # scheme 2: IV=first16, decrypt bytes[16:]
                if ivname=='firstblk' and mode in ('ctr','cfb','ofb','cbc'):
                    pt2=openssl_dec(mode,key,ct[:16].hex(),ct[16:])
                    if pt2:
                        s,e,pr,h=score(pt2)
                        results.append((s,bpath,kname,mode,'IV=blk0','skip16',e,pr,h,pt2[:32].hex()))
results.sort(reverse=True)
print(f"{'score':>6} {'blob':20} {'key':8} {'mode':4} {'iv':9} {'scheme':7} {'H':>5} {'prn':>4} {'hit':>3}  plaintext[:32]")
for r in results[:25]:
    s,bp,kn,md,iv,sc,e,pr,h,pth=r
    print(f"{s:6.2f} {os.path.basename(bp):20} {kn:8} {md:4} {iv:9} {sc:7} {e:5.2f} {pr:4.2f} {h:3d}  {pth}")

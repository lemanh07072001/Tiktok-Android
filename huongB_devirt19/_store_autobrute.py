#!/usr/bin/env python3
# AUTO-BRUTE: harvest key candidates from store_keygen.json (EINIT keys + G1/G2 retMem/memOut),
# derive raw/ascii-hex/ascii-bytes forms, then DIFF-decrypt fresh ground-truth .ms* across modes.
import os,glob,json,binascii,sys
from Crypto.Cipher import AES
KJSON=sys.argv[1] if len(sys.argv)>1 else 'cap.noindex/store_keygen.json'
OVDIRS=['cap.noindex/gt_*','cap.noindex/store_now_*/ovnow','cap.noindex/both/both/ov']
def load_ct():
    files={}
    for pat in OVDIRS:
        for d in sorted(glob.glob(pat)):
            for f in glob.glob(d+'/.ms*'):
                n=os.path.basename(f); b=open(f,'rb').read()
                if n not in files or len(b)>=len(files[n][1]): files[n]=(f,b)
    return files
def ishex(s):
    return len(s)>=2 and len(s)%2==0 and all(c in '0123456789abcdefABCDEF' for c in s)
def harvest(kj):
    """return set of candidate key-bytes (16/24/32) from keygen json."""
    cands=set(); ivs=set()
    if not os.path.exists(kj): return cands,ivs
    d=json.load(open(kj)); msgs=d.get('msgs',[])
    hexblobs=set()
    for m in msgs:
        if m.get('tag')=='EINIT':
            k=m.get('key'); iv=m.get('iv')
            if k and ishex(k): hexblobs.add(k)
            if iv and ishex(iv): ivs.add(binascii.unhexlify(iv))
        elif m.get('tag')=='GEN':
            for fld in ('retMem',):
                v=m.get(fld)
                if v: hexblobs.add(v)
            for arrn in ('memOut','memIn'):
                for v in (m.get(arrn) or []):
                    if v: hexblobs.add(v)
    for h in hexblobs:
        raw=binascii.unhexlify(h[: (len(h)//2)*2 ])
        # form1: raw bytes, take 16/24/32 prefix
        for L in (16,24,32):
            if len(raw)>=L: cands.add(raw[:L])
        # form2: if raw decodes to ASCII hex string, unhexlify THAT
        try:
            s=raw.decode('ascii')
            if ishex(s):
                inner=binascii.unhexlify(s)
                for L in (16,24,32):
                    if len(inner)>=L: cands.add(inner[:L])
            # form3: ASCII chars themselves as key bytes (16/32 ASCII chars)
            sb=s.encode('ascii')
            for L in (16,24,32):
                if len(sb)>=L: cands.add(sb[:L])
        except Exception: pass
    return cands,ivs
STATIC_KEYS=[binascii.unhexlify(x) for x in [
 '8252970d959b06db102e17d85c0ec1af','b114249b7bed9d2691d70c60d69f9c4f',
 'ebfc38403c4d52ae6761317d2b527dde','37a160ad3d6aa74b587977f4a2818b11']]
STATIC_IVS=[binascii.unhexlify(x) for x in [
 '4d207ea37a419f7d622f81c6a2f53594','00000000000000000000000000000000']]
def score(pt):
    if not pt: return 0.0
    n=len(pt); pr=sum(1 for c in pt if 32<=c<127 or c in (9,10,13))/n; b=0.0
    for kw in (b'sdi_v2',b'mssdk',b'device',b'{',b'ticket',b'"',b'http',b'cn=',b'id'):
        if kw in pt: b+=0.08
    if pt[:1] in (b'\x0a',b'\x08',b'{',b'['): b+=0.2
    return pr+b
def modes(ct,key,iv):
    out=[]; L=len(ct)
    try:
        from Crypto.Util import Counter
        c=Counter.new(128,initial_value=int.from_bytes(iv,'big'))
        pt=AES.new(key,AES.MODE_CTR,counter=c).decrypt(ct)
        if score(pt)>0.9: out.append(('CTR',score(pt),pt))
    except Exception: pass
    for md,nm in ((AES.MODE_CFB,'CFB'),(AES.MODE_OFB,'OFB')):
        try:
            a=AES.new(key,md,iv=iv,segment_size=128) if md==AES.MODE_CFB else AES.new(key,md,iv=iv)
            pt=a.decrypt(ct)
            if score(pt)>0.9: out.append((nm,score(pt),pt))
        except Exception: pass
    if L%16==0 and L>0:
        try:
            pt=AES.new(key,AES.MODE_ECB).decrypt(ct)
            if score(pt)>0.9: out.append(('ECB',score(pt),pt))
        except Exception: pass
        try:
            pt=AES.new(key,AES.MODE_CBC,iv=iv).decrypt(ct)
            if score(pt)>0.9: out.append(('CBC',score(pt),pt))
        except Exception: pass
    if L>16:
        for nonce in (iv[:12], ct[:12]):
            try:
                g=AES.new(key,AES.MODE_GCM,nonce=nonce)
                pt=g.decrypt_and_verify(ct[:-16],ct[-16:]); out.append(('GCM-OK',9.9,pt))
            except Exception: pass
    return out
def main():
    files=load_ct(); print('ct files:',len(files))
    hc,hiv=harvest(KJSON)
    keys=list({k for k in list(hc)+STATIC_KEYS}); ivs=list({v for v in list(hiv)+STATIC_IVS})
    print('candidate keys:',len(keys),' ivs:',len(ivs),' (from',KJSON,')')
    best=[]
    for name,(path,ct) in sorted(files.items()):
        variants=[(name,ct,None)]
        if len(ct)>16: variants.append((name+'[iv0]',ct[16:],ct[:16]))
        for vn,body,ivpfx in variants:
            for key in keys:
                iv_try=ivs+([ivpfx] if ivpfx else [])
                for iv in iv_try:
                    for nm,s,pt in modes(body,key,iv):
                        best.append((s,vn,binascii.hexlify(key).decode()[:12],binascii.hexlify(iv).decode()[:8],nm,pt[:64]))
    best.sort(reverse=True)
    if not best: print('NO HITS.'); return
    print('=== TOP HITS ===')
    for s,vn,k,iv,nm,pt in best[:25]:
        print('%.2f %-14s key=%s iv=%s %-8s %r'%(s,vn,k,iv,nm,pt))
if __name__=='__main__': main()

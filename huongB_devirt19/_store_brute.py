#!/usr/bin/env python3
# DIFF-test: brute captured key/iv candidates x .ms* ciphertext x AES modes.
# Standard AES (proven). Score plaintext by printable ratio / protobuf / known keynames.
import os,glob,sys,binascii
from Crypto.Cipher import AES
OVDIRS=['cap.noindex/gt_*','cap.noindex/store_now_*/ovnow','cap.noindex/both/both/ov']
def load_ct():
    files={}
    for pat in OVDIRS:
        for d in glob.glob(pat):
            for f in glob.glob(d+'/.ms*'):
                n=os.path.basename(f); b=open(f,'rb').read()
                if n not in files or len(b)>=len(files[n][1]): files[n]=(f,b)
    return files
KEYS_HEX=[
 '8252970d959b06db102e17d85c0ec1af',   # EINIT req-sign key
 'b114249b7bed9d2691d70c60d69f9c4f',   # key1
 'ebfc38403c4d52ae6761317d2b527dde',   # G1 raw out A
 '37a160ad3d6aa74b587977f4a2818b11',   # G1 raw out B
]
# allow extra keys via argv (hex)
for a in sys.argv[1:]:
    if len(a) in (32,48,64) and all(c in '0123456789abcdefABCDEF' for c in a): KEYS_HEX.append(a.lower())
IVS_HEX=[
 '4d207ea37a419f7d622f81c6a2f53594',   # EINIT iv
 '00000000000000000000000000000000',   # zero
]
def score(pt):
    if not pt: return 0.0
    n=len(pt); pr=sum(1 for c in pt if 32<=c<127 or c in (9,10,13))/n
    bonus=0.0
    for kw in (b'sdi_v2',b'mssdk',b'device',b'{',b'ticket',b'"',b'\x0a',b'http'):
        if kw in pt: bonus+=0.1
    if pt[:1] in (b'\x0a',b'\x08',b'{',b'['): bonus+=0.2
    return pr+bonus
def try_modes(name,ct,khex,ivhex):
    hits=[]
    key=binascii.unhexlify(khex); iv=binascii.unhexlify(ivhex)
    L=len(ct)
    # CTR (iv as initial counter)
    try:
        from Crypto.Util import Counter
        ctr=Counter.new(128,initial_value=int.from_bytes(iv,'big'))
        pt=AES.new(key,AES.MODE_CTR,counter=ctr).decrypt(ct); s=score(pt)
        if s>0.9: hits.append(('CTR',s,pt))
    except Exception: pass
    for mode,nm in ((AES.MODE_CFB,'CFB'),(AES.MODE_OFB,'OFB')):
        try:
            pt=AES.new(key,mode,iv=iv,segment_size=128 if mode==AES.MODE_CFB else None).decrypt(ct) if mode==AES.MODE_CFB else AES.new(key,mode,iv=iv).decrypt(ct)
            s=score(pt)
            if s>0.9: hits.append((nm,s,pt))
        except Exception: pass
    if L%16==0 and L>0:
        for mode,nm in ((AES.MODE_ECB,'ECB'),):
            try:
                pt=AES.new(key,AES.MODE_ECB).decrypt(ct); s=score(pt)
                if s>0.9: hits.append((nm,s,pt))
            except Exception: pass
        try:
            pt=AES.new(key,AES.MODE_CBC,iv=iv).decrypt(ct); s=score(pt)
            if s>0.9: hits.append(('CBC',s,pt))
        except Exception: pass
    # GCM: nonce=iv[:12], ct=body[:-16], tag=last16 (only if L>16)
    if L>16:
        for nonce in (iv[:12], ct[:12]):
            try:
                g=AES.new(key,AES.MODE_GCM,nonce=nonce)
                pt=g.decrypt_and_verify(ct[:-16],ct[-16:]); hits.append(('GCM-VERIFY',9.9,pt))
            except Exception: pass
    return hits
def main():
    files=load_ct(); print('ciphertext files:',len(files))
    best=[]
    for name,(path,ct) in sorted(files.items()):
        for khex in KEYS_HEX:
            for ivhex in IVS_HEX:
                for nm,s,pt in try_modes(name,ct,khex,ivhex):
                    best.append((s,name,khex[:8],ivhex[:8],nm,pt[:64]))
            # IVPREFIX: treat first 16B of file as IV, rest as ciphertext
            if len(ct)>16:
                ivp=ct[:16].hex(); body=ct[16:]
                for nm,s,pt in try_modes(name,body,khex,ivp):
                    best.append((s,name+'[iv0]',khex[:8],ivp[:8],nm+'*',pt[:64]))
    best.sort(reverse=True)
    if not best: print('NO HITS (no mode>0.9 for any key/iv/file).'); return
    print('=== TOP HITS ===')
    for s,name,k,iv,nm,pt in best[:20]:
        print('%.2f %-12s key=%s iv=%s %-10s %s'%(s,name,k,iv,nm,pt))
if __name__=='__main__': main()

#!/usr/bin/env python3
# FOCUSED brute: clean candidate keys x big .ms* files x modes, strict oracle.
# Strong signals: GCM tag-verify (definitive), PKCS7 valid padding, full-buffer printable>0.95.
import os,glob,binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
OVDIRS=['cap.noindex/gt_*','cap.noindex/store_now_*/ovnow','cap.noindex/both/both/ov']
def load_ct():
    files={}
    for pat in OVDIRS:
        for d in sorted(glob.glob(pat)):
            for f in glob.glob(d+'/.ms*'):
                n=os.path.basename(f); b=open(f,'rb').read()
                if n not in files or len(b)>=len(files[n]): files[n]=b
    return files
# clean candidates as (label, keybytes)
HEXSTR=['69c65eb55d99db36d7930f67a56c3f88','8fd6b14a691fe1b080863491fda3e89c']
RAW16 =['37a160ad3d6aa74b587977f4a2818b11','ebfc38403c4d52ae6761317d2b527dde',
        '8252970d959b06db102e17d85c0ec1af','b114249b7bed9d2691d70c60d69f9c4f']
KEYS=[]
for h in HEXSTR:
    KEYS.append(('unhex16:'+h[:8], binascii.unhexlify(h)))        # 16B AES-128
    KEYS.append(('ascii32:'+h[:8], h.encode()))                   # 32B AES-256
for h in RAW16:
    KEYS.append(('raw16:'+h[:8], binascii.unhexlify(h)))
IVS=[('einit',binascii.unhexlify('4d207ea37a419f7d622f81c6a2f53594')),
     ('zero',b'\x00'*16)]
def pkcs7_ok(pt):
    if not pt: return False
    n=pt[-1]
    return 1<=n<=16 and len(pt)>=n and all(c==n for c in pt[-n:])
def printable_ratio(pt):
    if not pt: return 0
    return sum(1 for c in pt if 32<=c<127 or c in (9,10,13))/len(pt)
def strong(pt,mode):
    if not pt: return None
    pr=printable_ratio(pt)
    if pr>0.95: return ('PRINT%.2f'%pr)
    if mode in ('CBC','ECB') and pkcs7_ok(pt):
        # padding valid AND the unpadded part reasonably printable/structured
        n=pt[-1]; body=pt[:-n]
        if printable_ratio(body)>0.85 or body[:1] in (b'\x0a',b'\x08',b'{',b'['):
            return 'PKCS7+n=%d'%n
    if pt[:1] in (b'\x0a',b'\x08') and pr>0.6: return 'PB?'   # protobuf-ish
    if b'sdi_v2' in pt or b'mssdk' in pt or b'ticket' in pt: return 'KEYWORD'
    return None
def try_all(name,ct):
    hits=[]; L=len(ct)
    # candidate ciphertext framings
    frames=[('whole',ct,None,None)]
    if L>16: frames.append(('ivpfx',ct[16:],ct[:16],None))       # [16 iv][ct]
    if L>28: frames.append(('aead',ct[12:-16],ct[:12],ct[-16:]))  # [12 nonce][ct][16 tag]
    for klbl,key in KEYS:
        if len(key) not in (16,24,32): continue
        for flbl,body,ivpfx,tag in frames:
            ivlist=list(IVS)+([('pfx',ivpfx)] if ivpfx else [])
            for ivl,iv in ivlist:
                # stream/CTR/CFB/OFB
                for md,nm in ((AES.MODE_CFB,'CFB'),(AES.MODE_OFB,'OFB')):
                    try:
                        a=AES.new(key,md,iv=iv,segment_size=128) if md==AES.MODE_CFB else AES.new(key,md,iv=iv)
                        pt=a.decrypt(body); r=strong(pt,nm)
                        if r: hits.append((name,klbl,flbl,ivl,nm,r,pt[:48]))
                    except Exception: pass
                try:
                    c=Counter.new(128,initial_value=int.from_bytes(iv,'big'))
                    pt=AES.new(key,AES.MODE_CTR,counter=c).decrypt(body); r=strong(pt,'CTR')
                    if r: hits.append((name,klbl,flbl,ivl,'CTR',r,pt[:48]))
                except Exception: pass
                if len(body)%16==0 and len(body)>0:
                    try:
                        pt=AES.new(key,AES.MODE_CBC,iv=iv).decrypt(body); r=strong(pt,'CBC')
                        if r: hits.append((name,klbl,flbl,ivl,'CBC',r,pt[:48]))
                    except Exception: pass
            if len(body)%16==0 and len(body)>0:
                try:
                    pt=AES.new(key,AES.MODE_ECB).decrypt(body); r=strong(pt,'ECB')
                    if r: hits.append((name,klbl,flbl,'-','ECB',r,pt[:48]))
                except Exception: pass
            # GCM with explicit tag (definitive)
            if tag is not None:
                for nlbl,nonce in [('pfx12',ivpfx if ivpfx and len(ivpfx)>=12 else body[:0]),('cthead',ct[:12]),('einit12',IVS[0][1][:12])]:
                    if len(nonce)!=12: continue
                    try:
                        g=AES.new(key,AES.MODE_GCM,nonce=nonce)
                        pt=g.decrypt_and_verify(body,tag); hits.append((name,klbl,flbl,'gcm:'+nlbl,'GCM-VERIFY!',pt[:48]))
                    except Exception: pass
    return hits
def main():
    files=load_ct()
    big={n:b for n,b in files.items() if len(b)>=32}
    print('files total=%d  big(>=32B)=%d'%(len(files),len(big)))
    for n in sorted(big): print('  %-46s %dB'%(n,len(big[n])))
    allhits=[]
    for n,b in sorted(big.items()): allhits+=try_all(n,b)
    print('=== HITS (%d) ==='%len(allhits))
    for h in allhits[:60]: print(h)
    if not allhits: print('none passed strict oracle.')
if __name__=='__main__': main()

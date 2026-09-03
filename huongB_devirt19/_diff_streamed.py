#!/usr/bin/env python3
# DIFF every captured key (streamed + dumped) against ground-truth store blobs, all AES modes.
# Success = GCM tag-verify OR a decrypt with high printable-ratio / low-entropy structure.
import sys,glob,os,json,math,binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM=None

SRC=sys.argv[1] if len(sys.argv)>1 else 'cap.noindex/evp_match_init.json'
GT=sorted(glob.glob('gt_fresh.noindex/.ms*'))
J=json.load(open(SRC))
keyset={}
for m in J.get('streamed_keys',[]): keyset[(int(m['kb']),m['key'])]=1
for k in (J.get('data',{}) or {}).get('keys',{}): 
    kb,kh=k.split(':'); keyset[(int(kb),kh)]=1
ivs=[m['iv'] for m in J.get('streamed_ivs',[])] + list((J.get('data',{}) or {}).get('ivs',{}).keys())
ivs=list(dict.fromkeys(ivs))
print('keys:',len(keyset),' ivs:',len(ivs))
for kb,kh in keyset: print('  key kb=%d %s'%(kb,kh))
for iv in ivs: print('  iv',iv)

def ent(b):
    if not b: return 0
    from collections import Counter; c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def printable(b):
    return sum(1 for x in b if 9<=x<=13 or 32<=x<=126)/max(1,len(b))
def score(pt):
    return printable(pt), round(ent(pt),2)
def plausible(pt):
    pr,H=score(pt)
    return (pr>0.85 and H<6.0) or any(m in pt for m in (b'{',b'"',b'device',b'\x08',b'aweme',b'http',b'id'))

def gcm_try(key,blob,nonce,ctlayout):
    if AESGCM is None: return None
    try:
        a=AESGCM(key)
        if ctlayout=='A': ct=blob  # AESGCM expects ct||tag
        else: ct=blob[12:]
        n=nonce
        return a.decrypt(n,ct,None)
    except Exception: return None

hits=[]
for kb,kh in keyset:
    key=binascii.unhexlify(kh)
    for p in GT:
        blob=open(p,'rb').read(); n=os.path.basename(p)[:22]
        # GCM: nonce candidates
        nonces=[]
        for iv in ivs:
            ivb=binascii.unhexlify(iv)
            nonces+= [ivb[:12], ivb]
        nonces+=[b'\x00'*12, blob[:12]]
        for nc in nonces:
            if len(nc)!=12: continue
            for lay in ('A','B'):
                pt=gcm_try(key,blob,nc,lay)
                if pt is not None:
                    hits.append(('GCM',kh,n,binascii.hexlify(nc).decode(),lay,score(pt)))
                    print('  *** GCM VERIFY',kh[:16],n,'nonce',binascii.hexlify(nc).decode()[:24],'lay',lay,'->',score(pt))
        # CTR/CFB/OFB
        for iv in ivs+['00'*16, binascii.hexlify(blob[:16]).decode()]:
            try: ivb=binascii.unhexlify(iv)
            except: continue
            if len(ivb)!=16: continue
            for mname,mode in (('CTR',modes.CTR(ivb)),('CFB',modes.CFB(ivb)),('OFB',modes.OFB(ivb))):
                try:
                    d=Cipher(algorithms.AES(key),mode,backend=default_backend()).decryptor()
                    pt=d.update(blob)+d.finalize()
                    if plausible(pt): 
                        hits.append((mname,kh,n,iv,'-',score(pt))); print('  ~ %s plausible'%mname,kh[:16],n,score(pt))
                except Exception: pass
        # ECB / CBC for block-aligned
        if len(blob)%16==0 and len(blob)>0:
            try:
                d=Cipher(algorithms.AES(key),modes.ECB(),backend=default_backend()).decryptor()
                pt=d.update(blob)+d.finalize()
                if plausible(pt): hits.append(('ECB',kh,n,'-','-',score(pt))); print('  ~ ECB plausible',kh[:16],n,score(pt))
            except: pass
            for iv in ivs+['00'*16]:
                try: ivb=binascii.unhexlify(iv)
                except: continue
                if len(ivb)!=16: continue
                try:
                    d=Cipher(algorithms.AES(key),modes.CBC(ivb),backend=default_backend()).decryptor()
                    pt=d.update(blob)+d.finalize()
                    if plausible(pt): hits.append(('CBC',kh,n,iv,'-',score(pt))); print('  ~ CBC plausible',kh[:16],n,iv[:16],score(pt))
                except: pass
print('===== TOTAL HITS:',len(hits))
for h in hits: print('  HIT',h)

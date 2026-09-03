#!/usr/bin/env python3
# Track C offline DIFF verifier. Consumes _grab_out.json (live oracle capture),
# derives candidate (key,iv) tuples, pulls fresh ground-truth store files, and
# DIFF-decrypts across AES modes. Definitive oracles, in priority order:
#   (1) in-window (ct-block, pt-block) pair from BDEC/STRM -> reproduce & match
#   (2) GCM tag verify (cryptographic proof)
#   (3) PKCS7 + printable / protobuf structure
import json, os, sys, subprocess, binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

ADB='/Users/lemanh/Library/Android/sdk/platform-tools/adb'
OV='/data/data/com.zhiliaoapp.musically/files/.msdata/mssdk/ov'
GT ='../cap.noindex/gt_live'
LOG=sys.argv[1] if len(sys.argv)>1 else '_grab_out.json'

def sh(*a,t=25):
    try: return subprocess.run(a,capture_output=True,timeout=t)
    except Exception as e: print('sh err',e); return None

def pull_gt():
    os.makedirs(GT,exist_ok=True)
    r=sh(ADB,'shell','su','0','find',OV,'-maxdepth','1','-name','.ms*')
    names=[x for x in (r.stdout.decode(errors='replace').split() if r and r.stdout else []) if '/.ms' in x]
    got={}
    for full in names:
        n=full.split('/')[-1]
        rr=sh(ADB,'exec-out','su','0','cat',full)
        if rr and rr.stdout:
            open(os.path.join(GT,n),'wb').write(rr.stdout); got[n]=rr.stdout
    return got

log=json.load(open(LOG))
# ---- candidate keys (raw bytes) ----
keys={}
for e in log:
    if e.get('t') in ('KSCH','EINIT') and e.get('userKey'):
        try: raw=bytes.fromhex(e['userKey'])
        except: continue
        kb=e.get('keyBytes',len(raw))
        for L in ({16,24,32} & {kb}) or {len(raw)}:
            if len(raw)>=L: keys.setdefault(raw[:L], e.get('t')+('*' if e.get('win') else ''))
        # also try the hex-string-as-ascii interpretation (MD5-shaped -> 32B AES256)
        if e.get('userKey') and all(c in '0123456789abcdef' for c in e['userKey']) and len(e['userKey'])==32:
            keys.setdefault(e['userKey'].encode(), 'ASCII32')
ivs={b'\x00'*16}
for e in log:
    if e.get('t')=='EINIT' and e.get('iv'):
        try: ivs.add(bytes.fromhex(e['iv'])[:16])
        except: pass

print('candidate keys:',len(keys),'  ivs:',len(ivs))
for k,src in keys.items(): print('   key['+src+']',k.hex(),'len',len(k))

gt=pull_gt()
print('ground-truth files:',len(gt))
big={n:b for n,b in gt.items() if len(b)>=16}

def printable(b):
    if not b: return 0.0
    ok=sum(1 for x in b if 9<=x<=13 or 32<=x<=126)
    return ok/len(b)

def strong(pt):
    if pt is None: return None
    pr=printable(pt)
    tags=[]
    if pr>0.95: tags.append('PRINT%.2f'%pr)
    # PKCS7
    if pt and 1<=pt[-1]<=16 and len(pt)>=pt[-1] and pt[-pt[-1]:]==bytes([pt[-1]])*pt[-1]:
        body=pt[:-pt[-1]]
        if printable(body)>0.85: tags.append('PKCS7+PRINT%.2f'%printable(body))
    # protobuf-ish (field 1-15, wiretype 0/2)
    if pt and (pt[0]&0x07) in (0,2) and 1<=(pt[0]>>3)<=15: tags.append('PB?')
    if b'{' in pt[:4] or b'ov' in pt[:8] or b'http' in pt[:16]: tags.append('KW')
    return tags or None

hits=[]
for n,ct in big.items():
    for k in keys:
        for iv in ivs:
            trials=[]
            # stream modes (length-preserving): CTR/CFB/OFB
            try: trials.append(('CTR',AES.new(k,AES.MODE_CTR,counter=Counter.new(128,initial_value=int.from_bytes(iv,'big'))).decrypt(ct)))
            except Exception: pass
            try: trials.append(('CFB',AES.new(k,AES.MODE_CFB,iv=iv,segment_size=128).decrypt(ct)))
            except Exception: pass
            try: trials.append(('OFB',AES.new(k,AES.MODE_OFB,iv=iv).decrypt(ct)))
            except Exception: pass
            if len(ct)%16==0:
                try: trials.append(('CBC',AES.new(k,AES.MODE_CBC,iv=iv).decrypt(ct)))
                except Exception: pass
                try: trials.append(('ECB',AES.new(k,AES.MODE_ECB).decrypt(ct)))
                except Exception: pass
            # GCM: [12 nonce][ct][16 tag]
            if len(ct)>=28:
                try:
                    g=AES.new(k,AES.MODE_GCM,nonce=ct[:12]); pt=g.decrypt_and_verify(ct[12:-16],ct[-16:])
                    hits.append((n,k.hex()[:12],'GCM-VERIFIED',pt[:32])); print('  *** GCM VERIFIED',n,k.hex()[:12])
                except Exception: pass
            for mode,pt in trials:
                s=strong(pt)
                if s: hits.append((n,keys[k],k.hex()[:12],mode,iv.hex()[:8],s,pt[:24]))

print('=== HITS',len(hits),'===')
for h in hits[:60]: print('  ',h)
if not hits: print('  (none) — captured keys do not decrypt store; store key not in this capture window')

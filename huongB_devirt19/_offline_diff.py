#!/usr/bin/env python3
# Offline DIFF: try captured firehose keys against ground-truth store blobs.
# Decisive oracle = AES-GCM tag verify. Also score CBC/CTR/ECB/CFB/OFB plaintext.
import os, glob, math, binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEYS = {
 'k1_b11424': binascii.unhexlify('b114249b7bed9d2691d70c60d69f9c4f'),
 'k2_825297': binascii.unhexlify('8252970d959b06db102e17d85c0ec1af'),
}
IVc = binascii.unhexlify('4d207ea37a419f7d622f81c6a2f53594')
ZERO = b'\x00'*16

DIR='gt_fresh.noindex'
blobs=sorted(glob.glob(DIR+'/.ms*'), key=lambda p:os.path.getsize(p))

def entropy(b):
    if not b: return 0
    from collections import Counter as C
    c=C(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def printable_ratio(b):
    if not b: return 0
    return sum(1 for x in b if 9<=x<=13 or 32<=x<=126)/len(b)
def looks_plain(b):
    pr=printable_ratio(b); e=entropy(b)
    # JSON/proto/text markers
    marker = any(m in b for m in (b'{',b'"',b'device',b'ticket',b'sec',b'\x0a',b'http'))
    return pr, e, marker
def score(pt):
    pr,e,mk=looks_plain(pt)
    s=pr*2 + (1 if mk else 0) + max(0,(4.0-e))  # low entropy + printable + markers
    return s,pr,e,mk

def ctr_dec(key, iv, ct):
    ctr=Counter.new(128, initial_value=int.from_bytes(iv,'big'))
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ct)

hits=[]
for p in blobs:
    blob=open(p,'rb').read(); L=len(blob); name=os.path.basename(p)
    print('\n=== %s (%dB) ===' % (name, L))
    cand=[]  # (score, tag, pt)
    for kn,key in KEYS.items():
        # ---- GCM (decisive) ----
        for nn,nonce in [('ivC12',IVc[:12]),('ivC16',IVc),('zero12',ZERO[:12]),
                         ('hdr12', blob[:12] if L>28 else None)]:
            if nonce is None: continue
            # layout A: ct=blob[:-16], tag=blob[-16:]
            if L>16:
                try:
                    c=AES.new(key,AES.MODE_GCM,nonce=nonce)
                    pt=c.decrypt_and_verify(blob[:-16], blob[-16:])
                    print('  ** GCM VERIFY ** key=%s nonce=%s layoutA  pt=%r' % (kn,nn,pt[:64]))
                    hits.append((name,kn,'GCM-'+nn+'-A',pt))
                except Exception: pass
            # layout B: nonce=blob[:12], ct=blob[12:-16], tag=last16
            if nn=='hdr12' and L>28:
                try:
                    c=AES.new(key,AES.MODE_GCM,nonce=blob[:12])
                    pt=c.decrypt_and_verify(blob[12:-16], blob[-16:])
                    print('  ** GCM VERIFY ** key=%s nonce=hdr layoutB pt=%r' % (kn,pt[:64]))
                    hits.append((name,kn,'GCM-hdr-B',pt))
                except Exception: pass
        # ---- CTR / CFB / OFB (stream; any length) ----
        for ivn,iv in [('ivC',IVc),('zero',ZERO),('hdr',blob[:16] if L>=16 else IVc)]:
            try: cand.append(score(ctr_dec(key,iv,blob))+(f'{kn}/CTR/{ivn}',ctr_dec(key,iv,blob)))
            except Exception: pass
            try:
                pt=AES.new(key,AES.MODE_CFB,iv=iv,segment_size=128).decrypt(blob)
                cand.append(score(pt)+(f'{kn}/CFB/{ivn}',pt))
            except Exception: pass
            try:
                pt=AES.new(key,AES.MODE_OFB,iv=iv).decrypt(blob)
                cand.append(score(pt)+(f'{kn}/OFB/{ivn}',pt))
            except Exception: pass
        # ---- ECB / CBC (block-aligned) ----
        if L%16==0 and L>0:
            try:
                pt=AES.new(key,AES.MODE_ECB).decrypt(blob); cand.append(score(pt)+(f'{kn}/ECB',pt))
            except Exception: pass
            for ivn,iv in [('ivC',IVc),('zero',ZERO)]:
                try:
                    pt=AES.new(key,AES.MODE_CBC,iv=iv).decrypt(blob); cand.append(score(pt)+(f'{kn}/CBC/{ivn}',pt))
                except Exception: pass
            if (L-16)%16==0 and L>16:  # embedded IV prefix
                try:
                    pt=AES.new(key,AES.MODE_CBC,iv=blob[:16]).decrypt(blob[16:]); cand.append(score(pt)+(f'{kn}/CBC/embIV',pt))
                except Exception: pass
    cand.sort(key=lambda t:-t[0])
    for s,pr,e,mk,tag,pt in cand[:3]:
        print('   %-16s score=%.2f pr=%.2f H=%.2f mk=%s  %r' % (tag,s,pr,e,mk,pt[:48]))

print('\n===== GCM HITS:', len(hits))
for h in hits: print('  ',h[0],h[1],h[2],repr(h[3][:80]))

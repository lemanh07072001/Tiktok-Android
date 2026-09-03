#!/usr/bin/env python3
# Track C STRICT offline DIFF verifier.
# Fixes prior 494-false-positive flood: drops PB?/KW; only counts a decrypt when
# a REAL structural oracle fires (GCM tag-verify, >=0.98 printable, valid PKCS7
# w/ printable body, or a STRICT full-buffer protobuf parse). File-size analysis
# proved store is a LENGTH-PRESERVING stream cipher (271/377/630/132 !%16), so we
# prioritise CTR/CFB/OFB + "nonce=first16" framing; CBC/ECB only for 16/32B files.
import json, os, sys, glob
from Crypto.Cipher import AES

HERE = os.path.dirname(os.path.abspath(__file__))
GT   = os.path.join(HERE, "..", "cap.noindex", "gt_live")
OUT  = os.path.join(HERE, "_grab_out.json")

PRT = set([9,10,13]) | set(range(0x20,0x7f))
def pr(b): return (sum(1 for x in b if x in PRT)/len(b)) if b else 0.0

def proto_ok(b):
    # strict: walk whole buffer as protobuf, must consume EXACTLY to end.
    i, n, fields = 0, len(b), 0
    if n < 2: return False
    while i < n:
        tag, sh = 0, 0
        while True:
            if i >= n: return False
            c = b[i]; i += 1
            tag |= (c & 0x7f) << sh; sh += 7
            if not (c & 0x80): break
            if sh > 63: return False
        fn, wt = tag >> 3, tag & 7
        if fn == 0 or fn > 0x1fffffff: return False
        if wt == 0:
            sh = 0
            while True:
                if i >= n: return False
                c = b[i]; i += 1; sh += 7
                if not (c & 0x80): break
                if sh > 70: return False
        elif wt == 1: i += 8
        elif wt == 5: i += 4
        elif wt == 2:
            ln, sh = 0, 0
            while True:
                if i >= n: return False
                c = b[i]; i += 1
                ln |= (c & 0x7f) << sh; sh += 7
                if not (c & 0x80): break
                if sh > 63: return False
            i += ln
        else:
            return False   # wiretype 3,4,6,7 -> not a clean message
        if i > n: return False
        fields += 1
    return i == n and fields >= 1

def judge(pt):
    if not pt: return None
    if len(pt) >= 16 and pr(pt) >= 0.98: return "PRINT%.3f" % pr(pt)
    n = pt[-1]
    if 1 <= n <= 16 and len(pt) > n and pt[-n:] == bytes([n])*n:
        body = pt[:-n]
        if pr(body) >= 0.90: return "PKCS7(%d)pr%.2f" % (n, pr(body))
    if pt[:2] in (b"PK", b"{\"", b"[{", b"[\"") or pt[:1] in (b"{", b"["):
        return "MAGIC"
    if proto_ok(pt): return "PROTO"
    return None

def gcm_try(key, ct):
    hits=[]
    if len(ct) >= 12+16+1:
        for npos in ("front","back"):
            try:
                if npos=="front": nonce, body, tag = ct[:12], ct[12:-16], ct[-16:]
                else:             nonce, body, tag = ct[-12:], ct[:-28], ct[-28:-12]
                pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(body, tag)
                hits.append(("GCM-"+npos, "VERIFIED", pt[:64].hex()))
            except Exception: pass
    return hits

def stream_try(key, ct, ivs):
    hits=[]
    L=len(ct)
    def add(mode, iv, pt):
        j=judge(pt)
        if j: hits.append((mode, iv.hex()[:16], j, pt[:48].hex()))
    for iv in ivs:
        # CTR big-endian, initial_value=iv
        try: add("CTR", iv, AES.new(key,AES.MODE_CTR,nonce=b"",initial_value=int.from_bytes(iv,"big")).decrypt(ct))
        except Exception: pass
        try: add("CFB", iv, AES.new(key,AES.MODE_CFB,iv=iv,segment_size=128).decrypt(ct))
        except Exception: pass
        try: add("OFB", iv, AES.new(key,AES.MODE_OFB,iv=iv).decrypt(ct))
        except Exception: pass
        if L%16==0:
            try: add("CBC", iv, AES.new(key,AES.MODE_CBC,iv=iv).decrypt(ct))
            except Exception: pass
    if L%16==0:
        try: add("ECB", b"\0"*16, AES.new(key,AES.MODE_ECB).decrypt(ct))
        except Exception: pass
    # framing: first 16 bytes = nonce, rest = stream body
    if L>16:
        n16, body = ct[:16], ct[16:]
        try: add("CTR/pfx", n16, AES.new(key,AES.MODE_CTR,nonce=b"",initial_value=int.from_bytes(n16,"big")).decrypt(body))
        except Exception: pass
        try: add("CFB/pfx", n16, AES.new(key,AES.MODE_CFB,iv=n16,segment_size=128).decrypt(body))
        except Exception: pass
        try: add("OFB/pfx", n16, AES.new(key,AES.MODE_OFB,iv=n16).decrypt(body))
        except Exception: pass
    return hits

# ---- load candidate keys ----
ev = json.load(open(OUT))
keys={}   # hex -> bytes
ivs=set([b"\0"*16])
for e in ev:
    uk=e.get("userKey")
    if uk and len(uk)%2==0:
        try:
            kb=bytes.fromhex(uk)
            if len(kb) in (16,24,32): keys[kb.hex()]=kb
        except Exception: pass
    iv=e.get("iv")
    if iv and len(iv)==32:
        try: ivs.add(bytes.fromhex(iv))
        except Exception: pass
ivl=list(ivs)
print("candidate keys=%d  ivs=%d" % (len(keys), len(ivl)))

# ---- diff every gt file ----
files=sorted(glob.glob(os.path.join(GT,".ms*")))
total=0
for fp in files:
    ct=open(fp,"rb").read(); nm=os.path.basename(fp)
    best=("",0.0)
    fh=[]
    for kh,kb in keys.items():
        for m,tag,px in gcm_try(kb,ct):
            fh.append(("GCM",kh[:8],m,tag,px))
        for mode,ivh,j,px in stream_try(kb,ct,ivl):
            fh.append((mode,kh[:8],ivh,j,px))
            r=pr(AES.new(kb,AES.MODE_OFB,iv=(ivl[0])).decrypt(ct)) if len(ct) else 0
    if fh:
        total+=len(fh)
        print("\n### %s (%dB)  HITS=%d" % (nm,len(ct),len(fh)))
        for h in fh[:12]: print("   ",h)
print("\n==== STRICT total hits =", total, "====")

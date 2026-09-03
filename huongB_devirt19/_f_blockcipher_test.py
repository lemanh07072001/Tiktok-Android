#!/usr/bin/env python3
# _f_blockcipher_test.py — attack slot16 = F(PSK, seed) as a 128-bit BLOCK CIPHER.
# slot16 is 16B = one 128-bit block. Test Speck128, Simon128, SM4, AES with:
#   (A) decrypt-and-look: D(key, slot16) -> does the SEED appear at a consistent offset,
#       with the rest CONSTANT across all 13 pairs?  (finds slot16 = E(key, seed||const))
#   (B) key=f(seed) forward: all-13 decrypt to the SAME block? (finds slot16 = E(kdf(seed), const))
# Self-validated by KATs before use. Ground truth = _corr_data.json (13 pairs, PSK constant).
import json, struct, sys
from Crypto.Cipher import AES
HAVE_SM4=True  # raw SM4 implemented below

# ---------------- SM4 raw single-block (no padding) ----------------
_SM4_SBOX=bytes([
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48])
def _rol32(x,r): return ((x<<r)|(x>>(32-r)))&0xffffffff
def _tau(a):
    return (_SM4_SBOX[(a>>24)&0xff]<<24)|(_SM4_SBOX[(a>>16)&0xff]<<16)|(_SM4_SBOX[(a>>8)&0xff]<<8)|_SM4_SBOX[a&0xff]
def _L(b): return b^_rol32(b,2)^_rol32(b,10)^_rol32(b,18)^_rol32(b,24)
def _Lp(b): return b^_rol32(b,13)^_rol32(b,23)
_FK=[0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc]
_CK=[]
for _i in range(32):
    _ck=0
    for _j in range(4): _ck=(_ck<<8)|(((_i*4+_j)*7)&0xff)
    _CK.append(_ck)
def sm4_rk(key):
    MK=[int.from_bytes(key[i*4:i*4+4],'big') for i in range(4)]
    K=[MK[i]^_FK[i] for i in range(4)]
    rk=[]
    for i in range(32):
        t=K[1]^K[2]^K[3]^_CK[i]
        k=K[0]^_Lp(_tau(t)); rk.append(k); K=[K[1],K[2],K[3],k]
    return rk
def sm4_block(inp, rk):
    X=[int.from_bytes(inp[i*4:i*4+4],'big') for i in range(4)]
    for i in range(32):
        t=X[1]^X[2]^X[3]^rk[i]
        x=X[0]^_L(_tau(t)); X=[X[1],X[2],X[3],x]
    return b''.join(X[3-i].to_bytes(4,'big') for i in range(4))
def sm4_encrypt(key,pt): return sm4_block(pt, sm4_rk(key))
def sm4_decrypt(key,ct): return sm4_block(ct, list(reversed(sm4_rk(key))))

# ---------------- Speck & Simon (word-size 64, 128-bit block) ----------------
MASK64=(1<<64)-1
def ror(x,r,n=64): return ((x>>r)|(x<<(n-r)))&MASK64
def rol(x,r,n=64): return ((x<<r)|(x>>(n-r)))&MASK64

def speck_key_schedule(key_words, rounds):
    # key_words: list of m 64-bit words, key_words[0] is the LOW word (k[0])
    m=len(key_words)
    k=[key_words[0]]
    l=list(key_words[1:])  # l[0..m-2]
    for i in range(rounds-1):
        li = l[i]  # current l
        new_l = (ror(li,8)+k[i])&MASK64 ^ i if False else (((ror(li,8)+k[i])&MASK64) ^ i)
        l.append(new_l)
        k.append(rol(k[i],3) ^ new_l)
    return k

def speck_encrypt_block(pt_hi, pt_lo, ks):
    x,y=pt_hi,pt_lo
    for kk in ks:
        x=((ror(x,8)+y)&MASK64) ^ kk
        y=rol(y,3) ^ x
    return x,y
def speck_decrypt_block(ct_hi, ct_lo, ks):
    x,y=ct_hi,ct_lo
    for kk in reversed(ks):
        y=ror(y ^ x,3)
        x=rol(((x ^ kk)-y)&MASK64,8)
    return x,y

SPECK_ROUNDS={2:32,3:33,4:34}  # m -> rounds for Speck128/128,192,256

# Simon128
def simon_z(seq_idx, length):
    Z=[
      0b01100111000011010100100010111110110011100001101010010001011111,
      0b01011010000110010011111011100010101101000011001001111101110001,
      0b11001101101001111110001000010100011001001011000000111011110101,
      0b11110000101100111001010001001000000111101001100011010111011011,
      0b11110111001001010011000011101000000100011011010110011110001011,
    ]
    z=Z[seq_idx]
    return [ (z>>(i)) &1 for i in range(length) ]  # LSB-first per spec usage below

def simon_key_schedule(key_words, rounds, seq_idx):
    m=len(key_words)
    k=list(key_words)
    zbits=[ (( [
      0x19C3522FB386A45F, # placeholder not used
    ] ) ) ]
    # standard z sequences (as bit lists), correct constants:
    ZSEQ=[
     "11111010001001010110000111001101111101000100101011000011100110",
     "10001110111110010011000010110101000111011111001001100001011010",
     "10101111011100000011010010011000101000010001111110010110110011",
     "11011011101011000110010111100000010010001010011100110100001111",
     "11010001111001101011011000100000010111000011001010010011101111",
    ]
    zs=ZSEQ[seq_idx]
    c=(1<<64)-4  # 0xff...fc
    for i in range(m, rounds):
        tmp=ror(k[i-1],3,64)
        if m==4:
            tmp ^= k[i-3]
        tmp ^= ror(tmp,1,64)
        zi=int(zs[(i-m)%62])
        k.append((~k[i-m] & MASK64) ^ tmp ^ zi ^ c)
    return k

def simon_encrypt_block(x,y,ks):
    for kk in ks:
        tmp=x
        x=(y ^ (rol(x,1)&rol(x,8)) ^ rol(x,2) ^ kk)&MASK64
        y=tmp
    return x,y
def simon_decrypt_block(x,y,ks):
    # inverse: iterate reversed; note final state (x,y) after enc; decrypt swaps roles
    for kk in reversed(ks):
        tmp=y
        y=(x ^ (rol(y,1)&rol(y,8)) ^ rol(y,2) ^ kk)&MASK64
        x=tmp
    return x,y

SIMON_ROUNDS={2:68,3:69,4:72}
SIMON_SEQ={2:2,3:3,4:4}

def b2w(b, bigendian=True):
    # split 16B into (hi,lo) 64-bit words
    if bigendian:
        hi=int.from_bytes(b[0:8],'big'); lo=int.from_bytes(b[8:16],'big')
    else:
        hi=int.from_bytes(b[0:8],'little'); lo=int.from_bytes(b[8:16],'little')
    return hi,lo
def w2b(hi,lo, bigendian=True):
    if bigendian:
        return hi.to_bytes(8,'big')+lo.to_bytes(8,'big')
    return hi.to_bytes(8,'little')+lo.to_bytes(8,'little')

def key_words(kb, bigendian=True):
    # kb bytes -> list of 64-bit words; word[0] is k[0]. Try both orderings by reversing.
    n=len(kb)//8
    ws=[]
    for i in range(n):
        chunk=kb[i*8:(i+1)*8]
        ws.append(int.from_bytes(chunk, 'big' if bigendian else 'little'))
    return ws

# ---------------- KAT self-validation ----------------
SIMON_OK=False
def kat():
    global SIMON_OK
    ok=True
    # Speck128/128
    key=bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    pt =bytes.fromhex("6c61766975716520 7469206564616d20".replace(" ",""))
    exp=bytes.fromhex("a65d985179783265 7860fedf5c570d18".replace(" ",""))
    kw=key_words(key,bigendian=True); kw=[kw[1],kw[0]]  # k[0]=low word
    ks=speck_key_schedule(kw, SPECK_ROUNDS[2])
    hi,lo=b2w(pt,True); ch,cl=speck_encrypt_block(hi,lo,ks); got=w2b(ch,cl,True)
    print("  Speck128/128 KAT:", "OK" if got==exp else "FAIL got=%s exp=%s"%(got.hex(),exp.hex()))
    ok &= got==exp
    # verify decrypt inverts
    dh,dl=speck_decrypt_block(ch,cl,ks); assert w2b(dh,dl,True)==pt, "speck dec"
    # Simon128/128
    pt2 =bytes.fromhex("6373656420737265 6c6c657661727420".replace(" ",""))
    exp2=bytes.fromhex("49681b1e1e54fe3f 65aa832af84e0bbc".replace(" ",""))
    kw2=key_words(key,True); kw2=[kw2[1],kw2[0]]
    ks2=simon_key_schedule(kw2, SIMON_ROUNDS[2], SIMON_SEQ[2])
    hi,lo=b2w(pt2,True); ch,cl=simon_encrypt_block(hi,lo,ks2); got2=w2b(ch,cl,True)
    SIMON_OK = (got2==exp2)
    print("  Simon128/128 KAT:", "OK" if SIMON_OK else "FAIL (Simon EXCLUDED from run)")
    if HAVE_SM4:
        # SM4 KAT
        k=bytes.fromhex("0123456789abcdeffedcba9876543210")
        p=bytes.fromhex("0123456789abcdeffedcba9876543210")
        e=bytes.fromhex("681edf34d206965e86b3e94f536e4246")
        got=sm4_encrypt(k,p)
        print("  SM4 KAT:", "OK" if got==e else "FAIL "+got.hex())
        print("  SM4 roundtrip:", "OK" if sm4_decrypt(k,got)==p else "FAIL")
        ok &= got==e
    return ok

# ---------------- load golden + keys ----------------
G=json.load(open('_corr_data.json'))
PSK=bytes.fromhex(G[0]['mat'])
pairs=[(bytes.fromhex(r['seed']), bytes.fromhex(r['slot16']), bytes.fromhex(r['rticket'].encode().hex()) if False else r['rticket']) for r in G]
seeds=[bytes.fromhex(r['seed']) for r in G]
slots=[bytes.fromhex(r['slot16']) for r in G]

# candidate keys
def load_embedded():
    keys={}
    keys['emb_19b520']=bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b")
    try:
        from elftools.elf.elffile import ELFFile
        f=open('bin/libmetasec_ov.so','rb'); elf=ELFFile(f)
        segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
        def rd(va,n):
            for v,o,sz in segs:
                if v<=va<v+sz:
                    f.seek(o+(va-v)); return f.read(n)
            return None
        for va,cnt,tag in [(0x960,5,'data960'),(0x17baa0,2,'rodata17baa0')]:
            b=rd(va,16*cnt)
            if b:
                for i in range(cnt): keys['%s_%d'%(tag,i)]=b[i*16:(i+1)*16]
    except Exception as e:
        print("[!] embedded extract:",e)
    return keys

KEYS={'PSK32':PSK,'PSK16lo':PSK[:16],'PSK16hi':PSK[16:],'PSK24':PSK[:24]}
KEYS.update(load_embedded())

def ciphers_decrypt(key, ct):
    """yield (name, plaintext16) for each cipher/keyorder that accepts this keylen."""
    out=[]
    kl=len(key)
    # AES
    if kl in (16,24,32):
        try: out.append(('AES%d'%(kl*8), AES.new(key,AES.MODE_ECB).decrypt(ct)));
        except Exception: pass
    # SM4 (128-bit key only)
    if HAVE_SM4 and kl==16:
        try: out.append(('SM4', sm4_decrypt(key,ct)))
        except Exception: pass
    # Speck / Simon 128-bit block, key 128/192/256
    if kl in (16,24,32):
        m=kl//8
        for be in (True,False):
            kw=key_words(key, be)
            for rev in (False,True):
                kwo = list(reversed(kw)) if rev else kw
                try:
                    ks=speck_key_schedule(kwo, SPECK_ROUNDS[m])
                    ch,cl=b2w(ct,be); dh,dl=speck_decrypt_block(ch,cl,ks)
                    out.append(('Speck128/%d_be%d_rev%d'%(kl*8,be,rev), w2b(dh,dl,be)))
                except Exception: pass
                if SIMON_OK:
                    try:
                        ks=simon_key_schedule(kwo, SIMON_ROUNDS[m], SIMON_SEQ[m])
                        ch,cl=b2w(ct,be); dh,dl=simon_decrypt_block(ch,cl,ks)
                        out.append(('Simon128/%d_be%d_rev%d'%(kl*8,be,rev), w2b(dh,dl,be)))
                    except Exception: pass
    return out

print("=== KAT ===");
if not kat(): print("[FATAL] core KAT (Speck/SM4/AES) failed — aborting"); sys.exit(1)

print("\n=== (A) decrypt-and-look: does SEED appear consistently in D(key,slot16)? ===")
# For each key & cipher, decrypt all 13 slots; xor across plaintexts -> constant bytes become 0.
# A hit = exactly the seed bytes vary and the varying region equals the seed (in some order/pos).
best=[]
for kn,kb in KEYS.items():
    # need cipher list determined per key; decrypt slot[0] to enumerate
    names=[n for n,_ in ciphers_decrypt(kb, slots[0])]
    for name in names:
        pts=[]
        for ct in slots:
            d=dict(ciphers_decrypt(kb,ct))
            pts.append(d.get(name))
        if any(p is None or len(p)!=16 for p in pts): continue
        # analyze variability
        varmask=bytearray(16)
        for j in range(16):
            s=set(p[j] for p in pts)
            varmask[j]=1 if len(s)>1 else 0
        nvar=sum(varmask)
        # does the varying region (4 contiguous bytes) equal seed (fwd or rev) in each pair?
        if nvar==0: continue
        # find contiguous varying run
        runs=[]; j=0
        while j<16:
            if varmask[j]:
                k=j
                while k<16 and varmask[k]: k+=1
                runs.append((j,k-j)); j=k
            else: j+=1
        # candidate: single run of length 4
        for (off,ln) in runs:
            if ln in (4,) :
                # check equals seed in some orientation across all pairs
                for orient in ('fwd','rev'):
                    okall=True
                    for idx in range(13):
                        chunk=pts[idx][off:off+4]
                        sd=seeds[idx] if orient=='fwd' else seeds[idx][::-1]
                        if chunk!=sd: okall=False; break
                    if okall:
                        best.append(('SEED-EXACT',kn,name,off,orient))
                        print("  *** SEED-EXACT HIT:",kn,name,"seed@off",off,orient)
        # also report low-variance (<=6 varying bytes) as structural clues
        if nvar<=6:
            best.append(('lowvar',kn,name,nvar,bytes(varmask).hex()))

if not any(b[0]=='SEED-EXACT' for b in best):
    print("  no exact seed-in-plaintext hit.")
    print("  low-variance structural candidates (nvar<=6):")
    lv=[b for b in best if b[0]=='lowvar']
    lv.sort(key=lambda x:x[3])
    for b in lv[:15]:
        print("   ",b[1],b[2],"nvar=",b[3],"mask=",b[4])

print("\n=== (B) key=f(seed): do all 13 decrypt to the SAME block? (slot16=E(kdf(seed),const)) ===")
# seed (4B) expanded to key: seed*4 (16B), seed||zeros, seed||PSK...  key candidates from seed.
def seed_keys(seed):
    ks={}
    ks['seedx4']=seed*4
    ks['seed_zero16']=seed+b'\x00'*12
    ks['seed_zero32']=seed+b'\x00'*28
    ks['seedx8']=seed*8  # 32B
    ks['seed_psk']=(seed+PSK)[:16]
    ks['seed_psk32']=(seed+PSK)[:32]
    return ks
for variant in ['seedx4','seed_zero16','seed_psk','seedx8','seed_zero32','seed_psk32']:
    for be in (True,False):
        # AES & SM4 & speck/simon
        # decrypt each slot with key=seed-derived, check equality
        results={}
        for idx in range(13):
            kb=seed_keys(seeds[idx])[variant]
            ds=dict(ciphers_decrypt(kb, slots[idx]))
            for name,pt in ds.items():
                results.setdefault(name,[]).append(pt)
        for name,lst in results.items():
            if len(lst)==13 and len(set(lst))==1:
                print("  *** CONST-BLOCK HIT: key=%s(%s) cipher=%s -> const=%s"%(variant,'be'if be else'le',name,lst[0].hex()))
        break  # be only affects key_words inside ciphers already; avoid dup
print("\n[done]")

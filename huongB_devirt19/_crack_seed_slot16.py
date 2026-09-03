#!/usr/bin/env python3
# Crack slot16 = Crypto(mat, seed) from 13 known (seed -> slot16) pairs (mat constant).
# Pure offline. Tries AES-128 ECB enc/dec over {key-derivation} x {block-construction},
# plus keyed-hash (md5/sha1/sha256) families. Declares hit only if it matches pair[0]
# AND verifies on all 13.
import hashlib, itertools, struct
import _aes_pure as A

MAT = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
PAIRS = [
 ("3d754937","621e717dd22e9feea3a3372f263aefba"),
 ("a24c8146","8ca462427dbfb3f3d431621b14f496ff"),
 ("6256ff02","efcdaa3d8e79bed47af9b0bac590929e"),
 ("9afb8327","f65dbce0123530770b7baf76b24cfde4"),
 ("de2cb364","b4678bc97849e132683add86a3bc764f"),
 ("c92bf87d","61580ce6ec1bd774f97272d20b8a5fc7"),
 ("d5543031","0b04cc917112a3f5668895aa003c9190"),
 ("4021715b","b6472e044f5d75ed4270e9005a632f99"),
 ("b6c6ab00","c138a4d7509c42ac997516a5f3d3f45b"),
 ("fc1a6313","3b4fa8c4a2237be4399c294a2961825d"),
 ("7f24785a","a748f1405cc52b2febb7acbbf2706be0"),
 ("e7862620","528c1749aaaa6bb985cf445ee1a1ad3f"),
 ("83ca0932","f59375d44d7e59fbe65f9ee7ffd03fd4"),
]
PAIRS=[(bytes.fromhex(s),bytes.fromhex(o)) for s,o in PAIRS]

def key_candidates():
    ks={}
    ks['mat[0:16]']=MAT[:16]
    ks['mat[16:32]']=MAT[16:]
    ks['mat[0:16]^mat[16:32]']=bytes(a^b for a,b in zip(MAT[:16],MAT[16:]))
    ks['md5(mat)']=hashlib.md5(MAT).digest()
    ks['md5(mathex)']=hashlib.md5(MAT.hex().encode()).digest()
    ks['sha256(mat)[:16]']=hashlib.sha256(MAT).digest()[:16]
    ks['sha1(mat)[:16]']=hashlib.sha1(MAT).digest()[:16]
    ks['mat_rev[0:16]']=MAT[:16][::-1]
    return ks

def block_candidates(seed):
    s=seed                    # 4 bytes as captured (big-endian hex order)
    sr=seed[::-1]
    z=b'\x00'
    b={}
    b['s+z12']=s+z*12
    b['sr+z12']=sr+z*12
    b['z12+s']=z*12+s
    b['z12+sr']=z*12+sr
    b['s*4']=s*4
    b['sr*4']=sr*4
    b['s+z12 (le at 0)']=struct.pack('<I',struct.unpack('>I',s)[0])+z*12
    b['md5(s)']=hashlib.md5(s).digest()
    b['md5(sr)']=hashlib.md5(sr).digest()
    # seed xored into mat halves
    b['mat0^ (s+z12)']=bytes(x^y for x,y in zip(MAT[:16], s+z*12))
    b['mat1^ (s+z12)']=bytes(x^y for x,y in zip(MAT[16:], s+z*12))
    return b

def hit_report(name, fn):
    ok=all(fn(s)==o for s,o in PAIRS)
    if ok:
        print(f"  *** FULL MATCH (all 13): {name}")
        return True
    # partial: count matches on pair0 only for signal
    if fn(PAIRS[0][0])==PAIRS[0][1]:
        print(f"  ~ pair0 match but not all: {name}")
    return False

found=False
KS=key_candidates()

# ---- AES ECB enc/dec: slot16 = AES(K, block(seed)) ----
for kn,K in KS.items():
    for direction,aesfn in (('enc',A.encrypt_block),('dec',A.decrypt_block)):
        # need a representative block-cand set; build per seed inside fn
        def make(kn=kn,K=K,aesfn=aesfn):
            def f(seed, bname):
                blk=block_candidates(seed)[bname]
                return aesfn(K,blk)
            return f
        # iterate block names using first seed's keyset
        for bname in block_candidates(PAIRS[0][0]).keys():
            nm=f"AES-{direction} K={kn} B={bname}"
            f=lambda seed,bname=bname,K=K,aesfn=aesfn: aesfn(K, block_candidates(seed)[bname])
            if hit_report(nm,f): found=True

# ---- double AES: AES(K2, AES(K1, block)) with K1,K2 = mat halves ----
for bname in block_candidates(PAIRS[0][0]).keys():
    nm=f"AES-enc-enc K1=mat0 K2=mat1 B={bname}"
    f=lambda seed,bname=bname: A.encrypt_block(MAT[16:],A.encrypt_block(MAT[:16],block_candidates(seed)[bname]))
    if hit_report(nm,f): found=True

# ---- keyed hash families: H(prefix || seed || suffix)[:16] ----
def hcands(seed):
    s=seed; sr=seed[::-1]
    combos={
      'md5(mat+s)':hashlib.md5(MAT+s).digest(),
      'md5(s+mat)':hashlib.md5(s+MAT).digest(),
      'md5(mat+sr)':hashlib.md5(MAT+sr).digest(),
      'md5(mathex+s)':hashlib.md5(MAT.hex().encode()+s).digest(),
      'md5(mathex+shex)':hashlib.md5((MAT.hex()+s.hex()).encode()).digest(),
      'sha1(mat+s)[:16]':hashlib.sha1(MAT+s).digest()[:16],
      'sha256(mat+s)[:16]':hashlib.sha256(MAT+s).digest()[:16],
      'sha256(s+mat)[:16]':hashlib.sha256(s+MAT).digest()[:16],
      'md5(mat0+s)':hashlib.md5(MAT[:16]+s).digest(),
      'md5(s+mat0)':hashlib.md5(s+MAT[:16]).digest(),
    }
    return combos
for hname in hcands(PAIRS[0][0]).keys():
    f=lambda seed,hname=hname: hcands(seed)[hname]
    if hit_report(hname,f): found=True

if not found:
    print("\nNo full match in this battery. Showing pair0 diagnostics for AES-enc K=mat[0:16] B=s+z12:")
    print("  seed:", PAIRS[0][0].hex(), "-> got:", A.encrypt_block(MAT[:16],PAIRS[0][0]+b'\0'*12).hex(), "want:", PAIRS[0][1].hex())
print("\nDone. found =", found)

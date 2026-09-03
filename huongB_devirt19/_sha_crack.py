#!/usr/bin/env python3
# SHA-256 là hash DUY NHẤT trong binary (K-table @file-off 0x19b540). Thử battery SHA-256/HMAC
# có hệ thống trên 13 cặp device-7666. slot16 = 16 byte.
import hashlib, hmac, struct, binascii
data=open('bin/libmetasec_ov.so','rb').read()

# verify full SHA-256 K table present
K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1]
off=0x19b540
ok=all(struct.unpack_from('<I',data,off+i*4)[0]==K[i] for i in range(len(K)))
print(f"SHA-256 K-table @0x19b540 verified (first {len(K)} words LE): {ok}")

MAT=bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
PAIRS=[("3d754937","621e717dd22e9feea3a3372f263aefba"),
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
("83ca0932","f59375d44d7e59fbe65f9ee7ffd03fd4")]
PAIRS=[(bytes.fromhex(s),bytes.fromhex(o)) for s,o in PAIRS]
S=lambda b: hashlib.sha256(b).digest()

def build_variants(seed):
    s=seed; sr=seed[::-1]; z=b'\0'
    m0,m1=MAT[:16],MAT[16:]
    V={}
    # direct concatenations
    V['sha(mat|s)']=S(MAT+s); V['sha(s|mat)']=S(s+MAT)
    V['sha(mat|sr)']=S(MAT+sr); V['sha(sr|mat)']=S(sr+MAT)
    V['sha(s|mat|s)']=S(s+MAT+s); V['sha(mat|s|mat)']=S(MAT+s+MAT)
    V['sha(mat^rep_s)']=S(bytes(a^b for a,b in zip(MAT, (s*8)[:32])))
    V['sha(m0|s)']=S(m0+s); V['sha(m1|s)']=S(m1+s)
    V['sha(s|m0)']=S(s+m0); V['sha(s|m1)']=S(s+m1)
    # 64-byte block (q2 is 64B): mat(32)|seed-fill(32)
    V['sha(mat|s*8)']=S(MAT+(s*8)); V['sha(mat|sr*8)']=S(MAT+(sr*8))
    V['sha(mat|s|z28)']=S(MAT+s+z*28)
    V['sha(mat|z28|s)']=S(MAT+z*28+s)
    V['sha(s*8|mat)']=S((s*8)+MAT)
    # double
    V['sha2(mat|s)']=S(S(MAT+s)); V['sha2(s|mat)']=S(S(s+MAT))
    # hmac both directions
    V['hmac(mat;s)']=hmac.new(MAT,s,hashlib.sha256).digest()
    V['hmac(s;mat)']=hmac.new(s,MAT,hashlib.sha256).digest()
    V['hmac(m0;s)']=hmac.new(m0,s,hashlib.sha256).digest()
    V['hmac(mat;s|mat)']=hmac.new(MAT,s+MAT,hashlib.sha256).digest()
    V['hmac(mathex;shex)']=hmac.new(MAT.hex().encode(),s.hex().encode(),hashlib.sha256).digest()
    # hex-string variants (many mobile impls hash hex ascii)
    V['sha(mathex|shex)']=S((MAT.hex()+s.hex()).encode())
    V['sha(shex|mathex)']=S((s.hex()+MAT.hex()).encode())
    return V

names=build_variants(PAIRS[0][0]).keys()
def slices(d):  # try [:16] and [16:32]
    return {'[:16]':d[:16],'[16:]':d[16:32],
            '[:16]^[16:]':bytes(a^b for a,b in zip(d[:16],d[16:32]))}
found=[]
for nm in names:
    for sl,_ in slices(b'\0'*32).items():
        okall=True
        for s,o in PAIRS:
            d=build_variants(s)[nm]
            got=slices(d)[sl]
            if got!=o: okall=False; break
        if okall:
            found.append(f"{nm} {sl}")
            print(f"  *** FULL MATCH: {nm} {sl}")
        else:
            # pair0 partial signal
            d0=build_variants(PAIRS[0][0])[nm]
            if slices(d0)[sl]==PAIRS[0][1]:
                print(f"  ~ pair0: {nm} {sl}")
print("\nfound=",found if found else "NONE")

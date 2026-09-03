#!/usr/bin/env python3
# Pure-Python AES(128/192/256)-GCM tag verifier — ZERO deps, offline.
# Track C §4 priority#1: decide whether store .msp/.mss/.msf3 = AES-GCM [ct||16B tag].

def _gmul(a,b):
    p=0
    for _ in range(8):
        if b&1: p^=a
        hi=a&0x80; a=(a<<1)&0xFF
        if hi: a^=0x1B
        b>>=1
    return p

def _init_sbox():
    inv=[0]*256
    for a in range(1,256):
        for b in range(a,256):
            if _gmul(a,b)==1:
                inv[a]=b; inv[b]=a; break
    sbox=[0]*256
    for i in range(256):
        s=inv[i]; x=s
        for _ in range(4):
            s=((s<<1)|(s>>7))&0xFF; x^=s
        sbox[i]=x^0x63
    return sbox
SBOX=_init_sbox()
RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D]

def key_expansion(key):
    Nk=len(key)//4; Nr=Nk+6
    w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk,4*(Nr+1)):
        t=list(w[i-1])
        if i%Nk==0:
            t=t[1:]+t[:1]; t=[SBOX[b] for b in t]; t[0]^=RCON[i//Nk-1]
        elif Nk>6 and i%Nk==4:
            t=[SBOX[b] for b in t]
        w.append([w[i-Nk][j]^t[j] for j in range(4)])
    return w,Nr

def aes_encrypt_block(block,w,Nr):
    s=[[block[r+4*c] for c in range(4)] for r in range(4)]
    def add(o):
        for c in range(4):
            for r in range(4): s[r][c]^=w[o+c][r]
    add(0)
    for rnd in range(1,Nr):
        for r in range(4):
            for c in range(4): s[r][c]=SBOX[s[r][c]]
        for r in range(1,4): s[r]=s[r][r:]+s[r][:r]
        for c in range(4):
            a=[s[r][c] for r in range(4)]
            s[0][c]=_gmul(a[0],2)^_gmul(a[1],3)^a[2]^a[3]
            s[1][c]=a[0]^_gmul(a[1],2)^_gmul(a[2],3)^a[3]
            s[2][c]=a[0]^a[1]^_gmul(a[2],2)^_gmul(a[3],3)
            s[3][c]=_gmul(a[0],3)^a[1]^a[2]^_gmul(a[3],2)
        add(4*rnd)
    for r in range(4):
        for c in range(4): s[r][c]=SBOX[s[r][c]]
    for r in range(1,4): s[r]=s[r][r:]+s[r][:r]
    add(4*Nr)
    return bytes(s[r][c] for c in range(4) for r in range(4))

def _gf_mult(X,Y):
    R=0xe1<<120; Z=0; V=X
    for i in range(128):
        if (Y>>(127-i))&1: Z^=V
        if V&1: V=(V>>1)^R
        else: V>>=1
    return Z
def _b2i(b): return int.from_bytes(b,'big')
def _i2b(x): return x.to_bytes(16,'big')
def ghash(H,data):
    y=0
    for i in range(0,len(data),16):
        blk=data[i:i+16]; blk=blk+b'\x00'*(16-len(blk))
        y=_gf_mult(y^_b2i(blk),H)
    return y

def _pad16(d): 
    return d + (b'\x00'*((16-len(d)%16)%16))

def gcm_verify_decrypt(key,nonce,ct,tag,aad=b''):
    w,Nr=key_expansion(key)
    H=_b2i(aes_encrypt_block(b'\x00'*16,w,Nr))
    if len(nonce)==12:
        J0=nonce+b'\x00\x00\x00\x01'
    else:
        s=ghash(H,_pad16(nonce)+(b'\x00'*8)+(len(nonce)*8).to_bytes(8,'big'))
        J0=_i2b(s)
    lenblk=(len(aad)*8).to_bytes(8,'big')+(len(ct)*8).to_bytes(8,'big')
    S=ghash(H,_pad16(aad)+_pad16(ct)+lenblk)
    EJ0=aes_encrypt_block(J0,w,Nr)
    calc=bytes(a^b for a,b in zip(_i2b(S),EJ0))
    if calc!=tag: return None
    ctr=_b2i(J0); pt=b''
    for i in range(0,len(ct),16):
        ctr=(ctr & ~((1<<32)-1))|((ctr+1)&((1<<32)-1))
        ks=aes_encrypt_block(_i2b(ctr),w,Nr)
        blk=ct[i:i+16]; pt+=bytes(a^b for a,b in zip(blk,ks))
    return pt

def selftest():
    assert gcm_verify_decrypt(b'\x00'*16,b'\x00'*12,b'',bytes.fromhex('58e2fccefa7e3061367f1d57a4e7455a'),b'')==b''
    key=bytes.fromhex('feffe9928665731c6d6a8f9467308308'); iv=bytes.fromhex('cafebabefacedbaddecaf888')
    ct=bytes.fromhex('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985')
    tag=bytes.fromhex('4d5c2af327cd64a62cf35abd2ba6fab4')
    pt=gcm_verify_decrypt(key,iv,ct,tag,b'')
    assert pt==bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255')
    # TC4 with AAD
    aad=bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    ct4=bytes.fromhex('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091')
    tag4=bytes.fromhex('5bc94fbc3221a5db94fae95ae7121a47')
    assert gcm_verify_decrypt(key,iv,ct4,tag4,aad) is not None
    print("[selftest] AES-GCM OK (NIST TC1+TC3+TC4/AAD pass)")

if __name__=='__main__': selftest()

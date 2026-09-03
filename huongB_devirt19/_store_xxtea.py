#!/usr/bin/env python3
"""TikTok mssdk store cipher — REVERSED (2026-08-31).
Chain: value -> wrapper 0x10dce0 -> XXTEA core 0x152310 -> fwrite 0x12e79c
       to file .msdata/mssdk/ov/<prefix>_SHA1(logical_key).
Cipher = XXTEA (delta 0x9e3779b9), key=16B per-value (arg x2), rounds=6+52/n.
Packing = little-endian u32 words, APPEND byte-length as final word.
Verified byte-exact vs 2 live (key,pt,ct) pairs captured from 0x152310."""
import struct, hashlib
DELTA=0x9e3779b9
def _rounds(n): return 6+52//n
def _enc(v,k):
    n=len(v)
    if n<2: return v
    s=0; z=v[-1]
    for _ in range(_rounds(n)):
        s=(s+DELTA)&0xffffffff; e=(s>>2)&3
        for p in range(n):
            y=v[(p+1)%n]
            mx=((((z>>5)^((y<<2)&0xffffffff))+((y>>3)^((z<<4)&0xffffffff)))&0xffffffff)^(((s^y)+(k[(p&3)^e]^z))&0xffffffff)
            v[p]=(v[p]+(mx&0xffffffff))&0xffffffff; z=v[p]
    return v
def _dec(v,k):
    n=len(v)
    if n<2: return v
    s=(_rounds(n)*DELTA)&0xffffffff; y=v[0]
    for _ in range(_rounds(n)):
        e=(s>>2)&3
        for p in range(n-1,-1,-1):
            z=v[(p-1)%n]
            mx=((((z>>5)^((y<<2)&0xffffffff))+((y>>3)^((z<<4)&0xffffffff)))&0xffffffff)^(((s^y)+(k[(p&3)^e]^z))&0xffffffff)
            v[p]=(v[p]-(mx&0xffffffff))&0xffffffff; y=v[p]
        s=(s-DELTA)&0xffffffff
    return v
def _b2w(b): 
    b=b+b'\0'*((-len(b))%4); return [struct.unpack('<I',b[i:i+4])[0] for i in range(0,len(b),4)]
def _w2b(w): return b''.join(struct.pack('<I',x) for x in w)
def key16(kh): kb=bytes.fromhex(kh) if isinstance(kh,str) else kh; return [struct.unpack('<I',kb[i:i+4])[0] for i in range(0,16,4)]
def encrypt(plaintext:bytes, key16hex)->bytes:
    v=_b2w(plaintext)+[len(plaintext)]
    return _w2b(_enc(v,key16(key16hex)))
def decrypt(ct:bytes, key16hex)->bytes:
    w=_dec([struct.unpack('<I',ct[i:i+4])[0] for i in range(0,len(ct),4)], key16(key16hex))
    n=w[-1]  # last word = original byte length
    return _w2b(w[:-1])[:n]
def filename(logical_key:str, prefix=".msf3_")->str:
    return prefix+hashlib.sha1(logical_key.encode()).hexdigest()

def store_key(logical_key:str)->str:
    "XXTEA 16-byte key = MD5(logical_key)"
    return hashlib.md5(logical_key.encode()).hexdigest()
def decrypt_store(logical_key:str, ciphertext:bytes)->bytes:
    "Fully-static: derive key=MD5(logical_key), XXTEA-decrypt. filename=SHA1(logical_key)."
    return decrypt(ciphertext, store_key(logical_key))

if __name__=="__main__":
    tests=[("a9aa231eb38ed0307fd6b9ed1721896c",b"1777072748","c91146d3f646a4b7b2fb1e4cfca5251f"),
           ("62e2ee76bb6db980e3634693c9420862",b"300","b8ebf6e291092c22")]
    for k,pt,ct in tests:
        e=encrypt(pt,k); d=decrypt(bytes.fromhex(ct),k)
        print(f"enc({pt})={e.hex()} {'OK' if e.hex()==ct else 'FAIL'}   dec={d} {'OK' if d==pt else 'FAIL'}")
    print("filename('sdi_v2','.msp_')=",filename("sdi_v2",".msp_"))

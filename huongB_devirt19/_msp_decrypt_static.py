#!/usr/bin/env python3
# _msp_decrypt_static.py — FULLY-STATIC offline decryptor for TikTok mssdk
# .msp/.mss device-secret stores (libmetasec_ov.so, crypt fn 0x10bbd0 = kind0).
# NO phone, NO emulator, NO deps (pure stdlib). Cracked 2026-09-02.
#
# Algorithm (verified vs cap.noindex/gt_live/.msp_092 & .msp_589):
#   filename   = SHA1(keyname).hex()                 (e.g. SHA1("sdi_v2")=092fde7a...)
#   key        = MD5( SHA1(keyname) ).hex()  (32 ASCII bytes)   == MD5(filename_bytes).hex()
#   keystream  = RC4(key)
#   inter      = ciphertext XOR keystream = [4-byte LE decompressed-len][zlib stream]
#   plaintext  = zlib.decompress(inter[4:])          (JSON)
# So a .msp file can be decrypted from its FILENAME alone (no keyname needed).
import zlib, hashlib, os, struct, json

def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256): j=(j+S[i]+key[i%len(key)])&255; S[i],S[j]=S[j],S[i]
    i=j=0; out=bytearray()
    for b in data:
        i=(i+1)&255; j=(j+S[i])&255; S[i],S[j]=S[j],S[i]; out.append(b^S[(S[i]+S[j])&255])
    return bytes(out)

def store_key(keyname: bytes) -> bytes:
    """key = MD5(SHA1(keyname)).hexdigest() as 32 ASCII bytes."""
    if isinstance(keyname,str): keyname=keyname.encode()
    return hashlib.md5(hashlib.sha1(keyname).digest()).hexdigest().encode()

def store_key_from_filename(name: str) -> bytes:
    """Derive key from a .msp_/.mss_ filename (its hex part = SHA1(keyname))."""
    base=os.path.basename(name)
    hexpart=base.split("_",1)[1] if "_" in base else base
    return hashlib.md5(bytes.fromhex(hexpart)).hexdigest().encode()

def decrypt(ciphertext: bytes, key: bytes):
    inter=rc4(key, ciphertext)
    # inter = [4-byte LE decompressed-len][zlib]; be tolerant of framing
    for off in (4,0,2,6,8):
        try:
            d=zlib.decompressobj().decompress(inter[off:])
            if d[:1] in (b'{',b'['): return d
        except Exception: pass
    return None

def decrypt_file(path: str):
    key=store_key_from_filename(path)
    return decrypt(open(path,"rb").read(), key)

if __name__=="__main__":
    import sys
    for p in sys.argv[1:] or []:
        d=decrypt_file(p)
        print("[%s] -> %s"%(os.path.basename(p), (d.decode('utf-8','replace')[:300] if d else "FAIL")))

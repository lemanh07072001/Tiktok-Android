from Crypto.Cipher import AES
keys={
 'K_enc':'8252970d959b06db102e17d85c0ec1af',
 'K_dec':'b8d72ddec05142948bbf2dc81d63759c',
 'K1_prev':'b114249b7bed9d2691d70c60d69f9c4f',
}
def score(b):
    pr=sum(1 for c in b if 9<=c<=13 or 32<=c<127)/max(1,len(b))
    return pr
def pkcs7_ok(b):
    if not b: return False
    n=b[-1]
    return 1<=n<=16 and b[-n:]==bytes([n])*n
import itertools
files={
 'msp_092f':open('_msdump_live2/msp_092f.bin','rb').read(),
 'mss_9b8e':open('_msdump_live2/mss_9b8e.bin','rb').read(),
 'msp_589c':open('_msdump_live2/msp_589c.bin','rb').read(),
}
print("### Hypothesis: [16B IV || ciphertext]")
for fn,data in files.items():
    iv=data[:16]; ct=data[16:]
    body=ct[:len(ct)//16*16]
    print(f"\n-- {fn}: iv={iv.hex()} bodylen={len(body)}")
    for kn,kh in keys.items():
        if len(body)==0: continue
        pt=AES.new(bytes.fromhex(kh),AES.MODE_CBC,iv).decrypt(body)
        print(f"   {kn}: pr={score(pt):.2f} pkcs7={pkcs7_ok(pt)} head={pt[:16].hex()} tail={pt[-4:].hex()}")
print("\n### Hypothesis: ECB (no IV), whole file")
for fn,data in files.items():
    body=data[:len(data)//16*16]
    for kn,kh in keys.items():
        pt=AES.new(bytes.fromhex(kh),AES.MODE_ECB).decrypt(body)
        s=score(pt)
        if s>0.7 or pkcs7_ok(pt):
            print(f"  {fn} {kn}: pr={s:.2f} pkcs7={pkcs7_ok(pt)} head={pt[:16].hex()}")

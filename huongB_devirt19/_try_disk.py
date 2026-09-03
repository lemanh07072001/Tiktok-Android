from Crypto.Cipher import AES
keys={
 'K_enc':'8252970d959b06db102e17d85c0ec1af',
 'K_dec':'b8d72ddec05142948bbf2dc81d63759c',
 'K1_prev':'b114249b7bed9d2691d70c60d69f9c4f',
}
ivs={
 'IV_enc':'4d207ea37a419f7d622f81c6a2f53594',
 'IV_dec':'d6c3969582f9ac5313d39c180b54a2bc',
 'IV0':'00000000000000000000000000000000',
}
def printable(b):
    return sum(1 for c in b if 9<=c<=13 or 32<=c<127)/max(1,len(b))
def looks_pb(b):
    # crude protobuf: first byte tag with field#>=1 wiretype in 0..5
    if not b: return False
    wt=b[0]&7; fn=b[0]>>3
    return wt in (0,1,2,5) and 1<=fn<=20
import sys
def trydec(name,data):
    print(f"\n### {name} ({len(data)}B) alignment%16={len(data)%16}")
    if len(data)%16!=0:
        # try skipping header so remainder %16==0
        for skip in range(0,16):
            if (len(data)-skip)%16==0 and len(data)-skip>=16:
                body=data[skip:]
                for kn,kh in keys.items():
                    for ivn,ivh in ivs.items():
                        try:
                            pt=AES.new(bytes.fromhex(kh),AES.MODE_CBC,bytes.fromhex(ivh)).decrypt(body)
                        except: continue
                        if printable(pt)>0.85 or looks_pb(pt):
                            print(f"  HIT skip={skip} {kn}/{ivn} pr={printable(pt):.2f} pb={looks_pb(pt)} head={pt[:24].hex()} :: {pt[:24]}")
        return
    for kn,kh in keys.items():
        for ivn,ivh in ivs.items():
            pt=AES.new(bytes.fromhex(kh),AES.MODE_CBC,bytes.fromhex(ivh)).decrypt(data)
            flag = printable(pt)>0.85 or looks_pb(pt)
            mark='  <== HIT' if flag else ''
            print(f"  {kn}/{ivn} pr={printable(pt):.2f} pb={looks_pb(pt)} head={pt[:20].hex()}{mark}")
import os
for f in ['msp_092f','mss_9b8e','msp_589c','msf3_5a78']:
    p=f'_msdump_live2/{f}.bin'
    trydec(f, open(p,'rb').read())

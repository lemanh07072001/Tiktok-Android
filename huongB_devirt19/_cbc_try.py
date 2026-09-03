from Crypto.Cipher import AES
KEYS={'K1_b114':'b114249b7bed9d2691d70c60d69f9c4f','K2_8252':'8252970d959b06db102e17d85c0ec1af','K3_b8d7':'b8d72ddec05142948bbf2dc81d63759c'}
IVS={'IV1_4d20':'4d207ea37a419f7d622f81c6a2f53594','IV2_d6c3':'d6c3969582f9ac5313d39c180b54a2bc','IVZ':'00'*16}
def show(tag,pt):
    asc=''.join(chr(x) if 32<=x<=126 else '.' for x in pt[:48])
    print(f"{tag:28} {pt[:24].hex()}  |{asc}|")
for fn in ['msp_092f','msp_589c','mss_9b8e']:
    data=open(f'_msdump_live/{fn}.bin','rb').read()
    print(f"\n########## {fn} ({len(data)}B) ##########")
    for skip in ([0] if len(data)%16==0 else [0]) + [1,2,3,7,11]:
        ct=data[skip:]
        if len(ct)%16: 
            # trim to block for CBC test
            ct2=ct[:len(ct)//16*16]
        else:
            ct2=ct
        if len(ct2)<16: continue
        for kn,kh in KEYS.items():
            for ivn,ivh in IVS.items():
                try:
                    pt=AES.new(bytes.fromhex(kh),AES.MODE_CBC,bytes.fromhex(ivh)).decrypt(ct2)
                except Exception as e: 
                    continue
                # only print if first byte plausibly protobuf OR high ascii
                asc=sum(1 for x in pt[:48] if 32<=x<=126 or x in (9,10,13))/min(48,len(pt))
                if pt[0] in (0x08,0x0a,0x10,0x12,0x18,0x1a,0x22,0x2a) or asc>0.6:
                    show(f"skip{skip} {kn} {ivn} CBC",pt)

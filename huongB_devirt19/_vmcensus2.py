#!/usr/bin/env python3
# Tách CODE vs DATA cho 35 program: đếm tỉ lệ opcode HỢP LỆ (∈ 47-handler).
# code thật → validFrac cao; blob data (S-box/const) → validFrac thấp.
# Với CODE, tính thêm marshFrac (op12/2a/2c) để tìm KDF ALU-nặng.
import struct
from collections import Counter
SO='bin/libmetasec_ov.so'; data=open(SO,'rb').read()
def u16(o): return struct.unpack_from('<H',data,o)[0]
def u32o(o): return struct.unpack_from('<I',data,o)[0]
def u64(o): return struct.unpack_from('<Q',data,o)[0]
e_phoff=u64(0x20); e_phes=u16(0x36); e_phn=u16(0x38)
SEGS=[]
for i in range(e_phn):
    o=e_phoff+i*e_phes
    if u32o(o)==1:
        p_off,p_va,_,p_fsz,p_msz=struct.unpack_from('<QQQQQ',data,o+8); SEGS.append((p_va,p_off,p_fsz))
def va2off(va):
    for p_va,p_off,p_fsz in SEGS:
        if p_va<=va<p_va+p_fsz: return p_off+(va-p_va)
    return None
VALID={1,3,4,5,6,7,8,9,12,13,15,17,18,19,20,22,23,24,25,26,28,30,33,36,37,38,40,41,42,43,44,45,46,47,48,49,50,52,53,54,55,56,57,59,60,61,63}
MARSH={0x12,0x2a,0x2c}
PROGS=sorted([0x17bbf0,0x17c0a0,0x17c750,0x17c880,0x17cbd0,0x17d9d0,0x17dd00,0x17de80,0x17e530,
0x17f940,0x17f9c0,0x1814f0,0x184780,0x184ed0,0x1863e0,0x186480,0x1864f0,0x186600,0x1873c0,
0x187e50,0x188370,0x188ee0,0x189250,0x189e30,0x18a510,0x18b020,0x18cd10,0x18f430,0x18fa80,
0x190140,0x1909b0,0x191f40,0x193130,0x193bf0,0x193e70])
ENDCAP=0x196000
NAMES={0x18f430:'seedgen',0x191f40:'F/marshal',0x1864f0:'report'}
print(f"{'prog':>10} {'size':>6} {'name':>10} validFrac marshFrac  verdict")
for idx,p in enumerate(PROGS):
    end=PROGS[idx+1] if idx+1<len(PROGS) else ENDCAP
    off=va2off(p); n=(end-p)//4
    c=Counter();
    for i in range(n): c[struct.unpack_from('<I',data,off+i*4)[0]&0x3f]+=1
    valid=sum(v for k,v in c.items() if k in VALID)
    marsh=sum(v for k,v in c.items() if k in MARSH)
    vf=valid/max(1,n); mf=marsh/max(1,valid)
    if vf<0.80: verdict='DATA/const-blob'
    elif mf>0.55: verdict='marshaller-code'
    else: verdict='*** ALU-CODE (KDF?) ***'
    print(f"{p:#010x} {(end-p):>6} {NAMES.get(p,''):>10}   {vf:.2f}     {mf:.2f}     {verdict}")

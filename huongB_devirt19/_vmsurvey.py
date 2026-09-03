#!/usr/bin/env python3
# Khảo sát 35 VM-program qua interpreter 0x52924 với frame-marker chung.
# Đo: instr reach, #native-call (blr x8 @0x5594c), #OUT-write, OUT[:32].
# KDF tự-chứa: ghi ~16B OUT, ít native-call, chạy sâu (không trap sớm vì thiếu object).
import struct
from unicorn import *
from unicorn.arm64_const import *
import _vm_emu as M

# (prog, tableA, tableB) từ _vmprogs.py (bỏ None)
PROGS=[
(0x17bbf0,0x1d9458,0x1d9460),(0x17c0a0,0x1d9db0,0x1d9de0),(0x17c750,0x1da160,0x1da170),
(0x17c880,0x1da190,0x1da1a0),(0x17cbd0,0x1da1f0,0x1da210),(0x17d9d0,0x1da718,0x1da730),
(0x17dd00,0x1da770,0x1da780),(0x17de80,0x1da7b0,0x1da7d0),(0x17e530,0x1da870,0x1da880),
(0x17f9c0,0x1db2b0,0x1db2d0),(0x1814f0,0x1db360,0x1db430),(0x184780,0x1db640,0x1db680),
(0x184ed0,0x1db6f0,0x1db730),(0x1864f0,0x1db7e8,0x1db7f0),(0x1873c0,0x1dc1f0,0x1dc250),
(0x187e50,0x1dc2e0,0x1dc320),(0x188370,0x1dc360,0x1dc3b0),(0x188ee0,0x1dc450,0x1dc480),
(0x189250,0x1dc4b0,0x1dc4d0),(0x189e30,0x1dc960,0x1dc9b0),(0x18a510,0x1dca30,0x1dca38),
(0x18b020,0x1dcad0,0x1dcaf0),(0x18cd10,0x1dcf48,0x1dcf50),(0x18f430,0x1dffe0,0x1e0000),
(0x18fa80,0x1e00c0,0x1e00d0),(0x190140,0x1e0140,0x1e0150),(0x1909b0,0x1e0200,0x1e0220),
(0x191f40,0x1e0530,0x1e0560),(0x193130,0x1e1428,0x1e1440),(0x193bf0,0x1e14e0,0x1e14f0),
(0x193e70,0x1e1520,0x1e1540),
]
NAMES={0x18f430:'seedgen',0x191f40:'F/marsh',0x1864f0:'report'}

def run(prog,taba,tabb,limit=300000):
    e=M.Emu(trace_native=True); uc=e.uc
    IN=M.INPUT_BASE; OUT=M.OUT_BASE
    buf=b''.join(struct.pack('<Q',0xAA00000000000000|i) for i in range(512))
    uc.mem_write(IN,buf); uc.mem_write(OUT,b'\0'*0x400)
    W=[]
    def hk_w(u,a,addr,sz,val,us):
        if OUT<=addr<OUT+0x400: W.append(addr-OUT)
    uc.hook_add(UC_HOOK_MEM_WRITE,hk_w)
    st={'n':0,'last':0}
    def hk_c(u,addr,sz,us):
        st['n']+=1; st['last']=addr
    uc.hook_add(UC_HOOK_CODE,hk_c)
    try:
        e.call(0x52924,[prog,IN,taba,tabb,OUT],count_limit=limit)
    except Exception as ex:
        pass
    out=bytes(uc.mem_read(OUT,32))
    return st['n'],len(e.native_log),len(set(W)),out

print(f"{'prog':>9} {'name':>8} {'instr':>7} {'nativ':>5} {'outB':>4}  OUT[:32]")
for prog,taba,tabb in PROGS:
    n,nat,outb,out=run(prog,taba,tabb)
    flag=''
    if 8<=outb<=32 and nat<=2: flag=' <== KDF-candidate'
    print(f"{prog:#09x} {NAMES.get(prog,''):>8} {n:>7} {nat:>5} {outb:>4}  {out.hex()}{flag}")

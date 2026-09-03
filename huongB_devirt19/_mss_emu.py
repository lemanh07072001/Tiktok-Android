#!/usr/bin/env python3
# _mss_emu.py — faithfully emulate the .mss (kind1) crypt primitive 0x10c158.
# Confirmed ABI (disasm getter 0x1184d0-0x118500):
#   0x10c158(x0=input MSString, x1=key MSString, x2=param MSString(""),
#            x3=&outlen(int*), w4=0, x8=out sret MSString)
# MSString = {u32 cap@0, u32 len@4, ptr data@8}
# key = MD5(SHA1("mssdk_setting")).hex = 5961b616...  (AES-256, universal derivation)
import sys, os, struct, importlib.util, zlib, hashlib
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
_spec=importlib.util.spec_from_file_location("e3","_msp_emu3.py")
e3=importlib.util.module_from_spec(_spec); sys.argv=["x"]; _spec.loader.exec_module(e3)
from unicorn import UcError
from unicorn.arm64_const import (UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X8,
    UC_ARM64_REG_LR,UC_ARM64_REG_PC)
base=e3.base

class Emu:
    def __init__(self):
        self.e=e3.Emu(); self.uc=self.e.uc; self.e.run_init(verbose=False)
    def mkstr(self,data):
        e,uc=self.e,self.uc
        p=e.alloc(len(data)+1); uc.mem_write(p,data+b"\x00")
        s=e.alloc(0x18); uc.mem_write(s,struct.pack("<IIQ",len(data),len(data),p)); return s
    def rdstr(self,s):
        uc=self.uc
        ln=struct.unpack_from("<I",bytes(uc.mem_read(s+4,4)),0)[0]
        dp=struct.unpack_from("<Q",bytes(uc.mem_read(s+8,8)),0)[0]
        return bytes(uc.mem_read(dp,ln)) if dp and 0<ln<(1<<22) else b""
    def call_10c158(self,inp,key,param=b"",w4=0,count=80000000,trace=False):
        e,uc=self.e,self.uc
        X0=self.mkstr(inp); X1=self.mkstr(key); X2=self.mkstr(param)
        X3=e.alloc(8); uc.mem_write(X3,b"\x00"*8)
        X8=e.alloc(0x18); uc.mem_write(X8,b"\x00"*0x18)
        uc.reg_write(UC_ARM64_REG_SP,e.sp0)
        uc.reg_write(UC_ARM64_REG_X0,X0); uc.reg_write(UC_ARM64_REG_X1,X1)
        uc.reg_write(UC_ARM64_REG_X2,X2); uc.reg_write(UC_ARM64_REG_X3,X3)
        uc.reg_write(UC_ARM64_REG_X4,w4); uc.reg_write(UC_ARM64_REG_X8,X8)
        uc.reg_write(UC_ARM64_REG_LR,e.RET)
        reached={"ret":False,"err":None,"pc":0}
        if trace:
            self.reads=[]
            from unicorn import UC_HOOK_MEM_READ
            def onrd(uc,acc,addr,size,val,ud):
                self.reads.append(addr)
            uc.hook_add(UC_HOOK_MEM_READ,onrd)
        try:
            uc.emu_start(base+0x10c158,e.RET,count=count); reached["ret"]=True
        except UcError as ex:
            reached["err"]=str(ex); reached["pc"]=uc.reg_read(UC_ARM64_REG_PC)
        outlen=struct.unpack_from("<i",bytes(uc.mem_read(X3,4)),0)[0]
        out=self.rdstr(X8)
        return out,outlen,reached

def check(p):
    """Look for [4B len][zlib], zlib magic anywhere, or JSON."""
    res=[]
    if len(p)>=6:
        ln=struct.unpack('<I',p[:4])[0]
        if 0<ln<200000 and p[4:6] in (b'\x78\x01',b'\x78\x9c',b'\x78\xda'):
            try:
                d=zlib.decompressobj().decompress(p[4:])
                res.append(("LENHDR+zlib",ln,len(d),d[:100]));
            except Exception as ex: res.append(("LENHDR-badzlib",ln,str(ex)))
    z=[i for i in range(len(p)-1) if p[i]==0x78 and p[i+1] in (0x01,0x9c,0xda)]
    for zp in z[:5]:
        try:
            d=zlib.decompressobj().decompress(p[zp:])
            if len(d)>3: res.append(("zlib@%d"%zp,len(d),d[:100]))
        except Exception: pass
    if p[:1] in (b'{',b'['): res.append(("json@0",p[:100]))
    return res,z

if __name__=="__main__":
    mss=open("../cap.noindex/gt_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d","rb").read()
    key=hashlib.md5(hashlib.sha1(b"mssdk_setting").digest()).hexdigest().encode()
    print("input=%dB key=%s"%(len(mss),key.decode()))
    cnt=int(sys.argv[1]) if len(sys.argv)>1 else 80000000
    em=Emu()
    for w4 in (0,1,2):
        em2=Emu()  # fresh state each direction
        out,outlen,reached=em2.call_10c158(mss,key,b"",w4=w4,count=cnt)
        print("\n==== w4=%d ===="%w4)
        print("reached RET:",reached["ret"],"err:",reached["err"],"pc:",hex(reached["pc"]))
        print("outlen field =",outlen," out MSString len =",len(out))
        print("out head:",out[:48].hex())
        print("out atxt:",repr(out[:64]))
        r,z=check(out)
        print("zlib-magic positions:",z[:10])
        print("CHECK:",r if r else "no structure found")

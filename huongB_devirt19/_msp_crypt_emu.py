#!/usr/bin/env python3
# _msp_crypt_emu.py — offline emulation of the .msp/.mss crypto primitives in
# libmetasec_ov.so (Unicorn). Runs from huongB_devirt19/ (needs _msp_emu3.py,
# _plt_map.json, bin/libmetasec_ov.so). venv: ~/.re-venv (unicorn+capstone).
#
# WHAT WORKS (verified this session):
#   keymat(keyname, mode)   -> 0x10b010 = MD5(keyname)  (mode even=raw16, odd=hex32)
#   sha1name(keyname, mode) -> 0x10b13c = SHA1(keyname) (=filename; even=raw20, odd=hex40)
#   crypt_keystream(key,n)  -> 0x10bbd0 = XOR-stream: crypt(X)=X ^ ks; ks=crypt(zeros).
#                              Reads ONLY static image + inputs (no device/session .bss).
#   ABI (empirically): 0x10bbd0(x0=input MSString, x1=key MSString, x8=out sret MSString)
#                      MSString = {u32 cap@0, u32 len@4, ptr data@8}
#
# OPEN GAP: the EXACT key the app passes to 0x10bbd0 is built by the read-getter
#   0x1182d0 (transforms MD5(keyname) via 0x14fe34/0x14fa94). It is NOT plain
#   MD5/SHA1(keyname) nor any device-secret value (~120 candidates tested, all miss).
#   Capturing it requires driving 0x1182d0, which spins in emulation on a lazy
#   C++ logger singleton [.bss 0x1fbaf8] (pthread_getspecific/TLS). See notes/56.
#
# Usage: from _msp_crypt_emu import Crypt; c=Crypt(); c.keymat(b"sdi_v2",0).hex()
import sys, os, struct, importlib.util, zlib
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
_spec=importlib.util.spec_from_file_location("e3","_msp_emu3.py")
e3=importlib.util.module_from_spec(_spec); sys.argv=["x"]; _spec.loader.exec_module(e3)
from unicorn import UcError
from unicorn.arm64_const import (UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X1,
                                 UC_ARM64_REG_X8,UC_ARM64_REG_LR)
base=e3.base

class Crypt:
    def __init__(self):
        self.e=e3.Emu(); self.uc=self.e.uc; self.e.run_init(verbose=False)
    def _mkstr(self,data):
        e,uc=self.e,self.uc
        p=e.alloc(len(data)+1); uc.mem_write(p,data+b"\x00")
        s=e.alloc(0x18); uc.mem_write(s,struct.pack("<IIQ",len(data),len(data),p)); return s
    def _rdstr(self,s):
        uc=self.uc
        ln=struct.unpack_from("<I",bytes(uc.mem_read(s+4,4)),0)[0]
        dp=struct.unpack_from("<Q",bytes(uc.mem_read(s+8,8)),0)[0]
        return bytes(uc.mem_read(dp,ln)) if dp and 0<ln<(1<<20) else b""
    def _call3(self,fn,x0,x1,x8,count=8000000):
        uc=self.uc
        uc.reg_write(UC_ARM64_REG_SP,self.e.sp0)
        uc.reg_write(UC_ARM64_REG_X0,x0); uc.reg_write(UC_ARM64_REG_X1,x1)
        uc.reg_write(UC_ARM64_REG_X8,x8); uc.reg_write(UC_ARM64_REG_LR,self.e.RET)
        try: uc.emu_start(base+fn,self.e.RET,count=count)
        except UcError: pass
    def keymat(self,keyname,mode=0):
        S=self._mkstr(keyname); O=self.e.alloc(0x18); self.uc.mem_write(O,b"\x00"*0x18)
        self._call3(0x10b010,S,mode,O,count=5000000); return self._rdstr(O)
    def sha1name(self,keyname,mode=0):
        S=self._mkstr(keyname); O=self.e.alloc(0x18); self.uc.mem_write(O,b"\x00"*0x18)
        self._call3(0x10b13c,S,mode,O,count=5000000); return self._rdstr(O)
    def crypt_keystream(self,keybytes,n):
        K=self._mkstr(keybytes); IN=self._mkstr(b"\x00"*n); O=self.e.alloc(0x18)
        self.uc.mem_write(O,b"\x00"*0x18); self._call3(0x10bbd0,IN,K,O); return self._rdstr(O)
    def decrypt(self,filebytes,keybytes):
        ks=self.crypt_keystream(keybytes,len(filebytes))
        inter=bytes(a^b for a,b in zip(filebytes,ks))
        for off in (0,4,2,6,8):
            try:
                d=zlib.decompressobj().decompress(inter[off:])
                if d[:1]==b'{': return d
            except Exception: pass
        return None

if __name__=="__main__":
    import hashlib
    c=Crypt()
    for m in (0,1):
        print("keymat(sdi_v2,%d)="%m, c.keymat(b"sdi_v2",m).hex())
    print("MD5(sdi_v2)     =", hashlib.md5(b"sdi_v2").hexdigest())
    print("sha1name(sdi_v2)=", c.sha1name(b"sdi_v2",0).hex(), "(=filename)")
    ks=c.crypt_keystream(hashlib.md5(b"sdi_v2").digest(),16)
    print("crypt_keystream(MD5(sdi_v2))[:16]=", ks.hex(), "(NOTE: not the app key -> won't decrypt; see notes/56)")

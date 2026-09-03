#!/usr/bin/env python3
# Unicorn harness cho libmetasec_ov.so — emulate hàm thật (không port tay).
# Mục tiêu: chạy interpreter F @0x52924 (VM prog 0x191f40) → đọc slot16.
# Env: .venv-emu (unicorn 2.1.4 + capstone 5.0.7).
import struct, sys
from unicorn import *
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

SO = 'bin/libmetasec_ov.so'
data = open(SO,'rb').read()

# ---- ELF parse ----
def u16(o): return struct.unpack_from('<H',data,o)[0]
def u32(o): return struct.unpack_from('<I',data,o)[0]
def u64(o): return struct.unpack_from('<Q',data,o)[0]
e_phoff=u64(0x20); e_phes=u16(0x36); e_phn=u16(0x38)
e_shoff=u64(0x28); e_shes=u16(0x3a); e_shn=u16(0x3c); e_shstrndx=u16(0x3e)

SEGS=[]
for i in range(e_phn):
    o=e_phoff+i*e_phes
    if u32(o)==1:  # PT_LOAD
        p_off,p_va,_,p_fsz,p_msz=struct.unpack_from('<QQQQQ',data,o+8)
        SEGS.append((p_va,p_off,p_fsz,p_msz))

sh=[struct.unpack_from('<IIQQQQIIQQ',data,e_shoff+i*e_shes) for i in range(e_shn)]
shstr=sh[e_shstrndx][4]
def snm(n):
    e=data.index(b'\0',shstr+n); return data[shstr+n:e].decode()
dynsym=dynstr=relaplt=None
for s in sh:
    nm=snm(s[0]); typ=s[1]
    if typ==11: dynsym=(s[4],s[9])
    if typ==3 and nm=='.dynstr': dynstr=s[4]
    if typ==4 and nm=='.rela.plt': relaplt=(s[4],s[5],s[9])
def dstr(n):
    e=data.index(b'\0',dynstr+n); return data[dynstr+n:e].decode()
def symname(idx):
    st_name=u32(dynsym[0]+idx*dynsym[1]*0 + idx*24)  # entsz=24
    return dstr(st_name)

# ---- Memory map layout ----
BASE      = 0x0                 # load base (module VMA == file VMA)
STACK_TOP = 0x7000_0000
STACK_SZ  = 0x0020_0000
HEAP_BASE = 0x1000_0000
HEAP_SZ   = 0x0800_0000
STUB_BASE = 0x0500_0000         # stub-land: 1 page per import
INPUT_BASE= 0x2000_0000         # input object-graph area
OUT_BASE  = 0x3000_0000         # output buffer
LR_SENTINEL = 0x4444_4444_0000  # return-address sentinel

def align_dn(x,a=0x1000): return x & ~(a-1)
def align_up(x,a=0x1000): return (x+a-1)&~(a-1)

class Emu:
    def __init__(self, trace_native=False, trace_load=False, verbose=False):
        self.uc=Uc(UC_ARCH_ARM64,UC_MODE_LITTLE_ENDIAN)
        self.md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
        self.hp=HEAP_BASE
        self.import_names={}   # stub_addr -> name
        self.verbose=verbose
        self.trace_native=trace_native
        self.native_log=[]
        self.load_log=[]
        self._map_segments()
        self._map_regions()
        self._apply_relative_relocs()
        self._wire_plt_stubs()
        self._install_hooks()

    def _map_segments(self):
        for va,fo,fsz,msz in SEGS:
            start=align_dn(BASE+va); end=align_up(BASE+va+msz)
            self.uc.mem_map(start,end-start)
            self.uc.mem_write(BASE+va, data[fo:fo+fsz])

    def _map_regions(self):
        self.uc.mem_map(align_dn(STACK_TOP-STACK_SZ),STACK_SZ)
        self.uc.mem_map(HEAP_BASE,HEAP_SZ)
        self.uc.mem_map(STUB_BASE,0x0010_0000)
        self.uc.mem_map(INPUT_BASE,0x0100_0000)
        self.uc.mem_map(OUT_BASE,0x0010_0000)

    def _apply_relative_relocs(self):
        # .rela.dyn RELATIVE (1027): *(off) = BASE + addend
        for s in sh:
            if s[1]==4 and snm(s[0])=='.rela.dyn':
                off,size,ent=s[4],s[5],s[9]
                for i in range(size//ent):
                    r_off,r_info,r_add=struct.unpack_from('<QQq',data,off+i*ent)
                    if (r_info&0xffffffff)==1027:
                        self.uc.mem_write(BASE+r_off, struct.pack('<Q',(BASE+r_add)&0xffffffffffffffff))

    def _wire_plt_stubs(self):
        off,size,ent=relaplt
        for i in range(size//ent):
            r_off,r_info,r_add=struct.unpack_from('<QQq',data,off+i*ent)
            sym=r_info>>32
            nm=symname(sym)
            stub=STUB_BASE + i*0x40
            self.import_names[stub]=nm
            # GOT[r_off] = stub addr; stub is a single BR-to-self trapped by code hook
            self.uc.mem_write(BASE+r_off, struct.pack('<Q',stub))
            # put a RET at stub so if ever executed w/o hook it returns; we hook before exec
            self.uc.mem_write(stub, struct.pack('<I',0xd65f03c0))  # ret

    # ---- allocator ----
    def alloc(self,n,align=16):
        self.hp=align_up(self.hp,align); p=self.hp; self.hp+=align_up(n,align); return p

    # ---- hooks ----
    def _install_hooks(self):
        self.uc.hook_add(UC_HOOK_CODE,self._hk_code)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED,self._hk_unmapped)

    def _hk_unmapped(self,uc,access,address,size,value,user):
        # lazily map any wild access so we can observe rather than crash
        pg=align_dn(address)
        try:
            uc.mem_map(pg,0x1000)
            return True
        except UcError:
            return True

    def _hk_code(self,uc,address,size,user):
        # intercept import stubs
        nm=self.import_names.get(address)
        if nm is not None:
            self._do_import(uc,nm)
            return
        # native-call trace
        if self.trace_native and address==0x5594c:
            x8=uc.reg_read(UC_ARM64_REG_X8); x0=uc.reg_read(UC_ARM64_REG_X0)
            self.native_log.append((x8,x0))

    def _ret(self,uc,val=0):
        uc.reg_write(UC_ARM64_REG_X0,val&0xffffffffffffffff)
        lr=uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_PC,lr)

    def _do_import(self,uc,nm):
        R=lambda i: uc.reg_read(getattr(__import__('unicorn.arm64_const',fromlist=['x']),f'UC_ARM64_REG_X{i}'))
        x0=uc.reg_read(UC_ARM64_REG_X0); x1=uc.reg_read(UC_ARM64_REG_X1)
        x2=uc.reg_read(UC_ARM64_REG_X2)
        if nm in ('malloc','_Znwm','_Znam'):
            self._ret(uc,self.alloc(x0 or 16)); return
        if nm=='calloc':
            p=self.alloc((x0*x1) or 16); uc.mem_write(p,b'\0'*((x0*x1) or 16)); self._ret(uc,p); return
        if nm=='realloc':
            p=self.alloc(x1 or 16)
            if x0 and x1:
                try: uc.mem_write(p,bytes(uc.mem_read(x0,x1)))
                except UcError: pass
            self._ret(uc,p); return
        if nm in ('free','_ZdlPv','_ZdaPv'): self._ret(uc,0); return
        if nm=='memcpy' or nm=='memmove':
            if x2: uc.mem_write(x0,bytes(uc.mem_read(x1,x2))); self._ret(uc,x0); return
        if nm=='memset':
            if x2: uc.mem_write(x0,bytes([x1&0xff])*x2); self._ret(uc,x0); return
        if nm=='memcmp':
            a=bytes(uc.mem_read(x0,x2)); b=bytes(uc.mem_read(x1,x2))
            self._ret(uc, 0 if a==b else (1 if a>b else (1<<64)-1)); return
        if nm in ('strlen','__strlen_chk'):
            n=0
            while uc.mem_read(x0+n,1)[0]!=0: n+=1
            self._ret(uc,n); return
        # default: no-op returning 0
        self._ret(uc,0)

    # ---- call helper ----
    def call(self, addr, args, out_reg=UC_ARM64_REG_X0, count_limit=50_000_000):
        for i,a in enumerate(args[:8]):
            uc=self.uc
            uc.reg_write(getattr(sys.modules['unicorn.arm64_const'],f'UC_ARM64_REG_X{i}'),a&0xffffffffffffffff)
        sp=STACK_TOP-0x1000
        self.uc.reg_write(UC_ARM64_REG_SP,sp)
        self.uc.reg_write(UC_ARM64_REG_LR,LR_SENTINEL)
        try:
            self.uc.emu_start(addr, LR_SENTINEL, count=count_limit)
        except UcError as e:
            pc=self.uc.reg_read(UC_ARM64_REG_PC)
            print(f"[emu-stop] {e} at pc={pc:#x}")
        return self.uc.reg_read(out_reg)

if __name__=='__main__':
    e=Emu(trace_native=True, verbose=True)
    print("harness built OK; segments mapped; relocs applied; %d imports stubbed"%len(e.import_names))
    print("stub sample:", {hex(k):v for k,v in list(e.import_names.items())[:3]})

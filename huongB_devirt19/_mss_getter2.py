#!/usr/bin/env python3
# _mss_getter2.py — full read-getter emulation for .mss.
# Strategy: (1) stateful pthread TLS/once/key_create; (2) SHORT-CIRCUIT the lazy
# logger getter 0x13af68 to return a controlled fake object whose vtable slots all
# point to a Python-hooked no-op stub (return `this`, safe for chaining/logic).
# Goal: let the worker 0x12f290 run its container-parse + AES decrypt to plaintext.
import sys, os, struct, importlib.util
_argv=sys.argv[1:]
_here=os.path.dirname(os.path.abspath(__file__)); os.chdir(_here)
_spec=importlib.util.spec_from_file_location("e3","_msp_emu3.py")
e3=importlib.util.module_from_spec(_spec); sys.argv=["x"]; _spec.loader.exec_module(e3)
from unicorn import UC_HOOK_CODE, UC_HOOK_INTR, UcError
from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,
    UC_ARM64_REG_X8,UC_ARM64_REG_LR,UC_ARM64_REG_PC)
import collections as _c
base=e3.base
_orig_plt=e3.Emu.plt
LOGGER_GETTER=0x13af68   # returns the lazy logger singleton (spins in emu)

def patched_plt(self,uc,addr,size,ud):
    fn=e3.PLT.get(addr-base)
    if fn is None: return
    if not hasattr(self,"tls"): self.tls={}; self.keys=1; self.once=set()
    lr=uc.reg_read(UC_ARM64_REG_LR)
    x0=uc.reg_read(UC_ARM64_REG_X0); x1=uc.reg_read(UC_ARM64_REG_X1)
    def ret(v=0): uc.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff); uc.reg_write(UC_ARM64_REG_PC,lr)
    if fn=="pthread_key_create":
        kid=self.keys; self.keys+=1
        try: uc.mem_write(x0,struct.pack("<I",kid))
        except Exception: pass
        self.tls[kid]=0; return ret(0)
    if fn=="pthread_key_delete": return ret(0)
    if fn=="pthread_setspecific": self.tls[x0&0xffffffff]=x1; return ret(0)
    if fn=="pthread_getspecific": return ret(self.tls.get(x0&0xffffffff,0))
    if fn=="pthread_once":
        if x0 in self.once: return ret(0)
        self.once.add(x0); uc.reg_write(UC_ARM64_REG_LR,lr); uc.reg_write(UC_ARM64_REG_PC,x1); return
    if fn=="_ZNSt6__ndk111__call_onceERVmPvPFvS2_E":
        x2=uc.reg_read(UC_ARM64_REG_X2)
        if x0 in self.once: return ret(0)
        self.once.add(x0); uc.reg_write(UC_ARM64_REG_X0,x1)
        uc.reg_write(UC_ARM64_REG_LR,lr); uc.reg_write(UC_ARM64_REG_PC,x2); return
    return _orig_plt(self,uc,addr,size,ud)
e3.Emu.plt=patched_plt

class Emu2(e3.Emu):
    def __init__(self,trace=False):
        super().__init__()
        uc=self.uc
        sc=base+0x30300000
        self.safe=sc+0x8000  # a valid non-null self-referential scratch object
        uc.mem_write(self.safe, struct.pack("<Q",self.safe)+b"\x00"*0xf8)
        # pre-seed the global log-sink singleton *(0x1efbd8) = safe (non-null)
        try: uc.mem_write(base+0x1efbd8, struct.pack("<Q",self.safe))
        except UcError: pass
        # pre-seed the SDK indirect allocator fptr table (set lazily at 0x17515c, null after init_array):
        #   *(0x1f3bc8)=alloc, *(0x1f3bd0)=free/dealloc, *(0x1f3bd8)=realloc  -> PLT stubs (plt hook handles)
        try:
            uc.mem_write(base+0x1f3bc8, struct.pack("<Q",base+0x30610))  # malloc
            uc.mem_write(base+0x1f3bd0, struct.pack("<Q",base+0x30590))  # free
            uc.mem_write(base+0x1f3bd8, struct.pack("<Q",base+0x30760))  # realloc
        except UcError: pass
        self.stub_hits=0; self.last=[]; self.trace=trace
        # bypass sink vtable call #1 at 0x13b010 (writes result ptr to [sp]) -> 0x13b014
        uc.hook_add(UC_HOOK_CODE, self._skip_vt1, begin=base+0x13b010, end=base+0x13b013)
        # bypass sink vtable call #2 at 0x13b034 (void) -> 0x13b038
        uc.hook_add(UC_HOOK_CODE, self._skip_vt2, begin=base+0x13b034, end=base+0x13b037)
        self.autoskip=bool(int(os.environ.get("AUTOSKIP","0")))
        self.skipped=[]
        self.syscalls=_c.Counter()
        self.fds={}; self.nextfd=3; self.opens=[]; self.filedata=b""
        uc.hook_add(UC_HOOK_INTR, self._svc)
        if self.autoskip:
            uc.hook_add(UC_HOOK_CODE, self._auto)
        if trace:
            uc.hook_add(UC_HOOK_CODE, self._tr)
    def _auto(self,uc,addr,size,ud):
        # auto-skip `blr xN` whose target is 0 or unmapped (measure vtable cascade depth)
        try: insn=struct.unpack("<I",bytes(uc.mem_read(addr,4)))[0]
        except UcError: return
        if (insn & 0xFFFFFC1F)==0xD63F0000:  # BLR Xn
            rn=(insn>>5)&0x1f
            from unicorn.arm64_const import UC_ARM64_REG_X0 as _x0
            tgt=uc.reg_read(_x0+rn) if rn<29 else 0
            bad = tgt==0
            if not bad:
                try: uc.mem_read(tgt,4)
                except UcError: bad=True
            if bad:
                self.skipped.append((addr-base, (uc.reg_read(_x0)) & 0xffffffffff))
                lr=uc.reg_read(UC_ARM64_REG_LR)  # not the call's LR; blr not executed yet
                uc.reg_write(UC_ARM64_REG_X0,0)
                uc.reg_write(UC_ARM64_REG_PC,addr+4)  # skip the call
    def _skip_vt1(self,uc,addr,size,ud):
        self.stub_hits+=1
        x1=uc.reg_read(UC_ARM64_REG_X1)
        try: uc.mem_write(x1, struct.pack("<Q",self.safe))
        except UcError: pass
        uc.reg_write(UC_ARM64_REG_PC,base+0x13b014)
    def _skip_vt2(self,uc,addr,size,ud):
        uc.reg_write(UC_ARM64_REG_PC,base+0x13b038)
    def _rdcstr(self,uc,p,n=512):
        try:
            d=bytes(uc.mem_read(p,n)); z=d.find(b"\x00"); return d[:z if z>=0 else n]
        except UcError: return b""
    def _svc(self,uc,intno,ud):
        # Linux arm64 syscall VFS: serve the store file content so the worker parses it.
        nr=uc.reg_read(UC_ARM64_REG_X8); self.syscalls[nr]+=1
        x0=uc.reg_read(UC_ARM64_REG_X0); x1=uc.reg_read(UC_ARM64_REG_X1)
        x2=uc.reg_read(UC_ARM64_REG_X2)
        R=lambda v: uc.reg_write(UC_ARM64_REG_X0, v&0xffffffffffffffff)
        content=self.filedata
        if nr==0x38:         # openat(dirfd, pathname, flags, mode)
            path=self._rdcstr(uc,x1); self.opens.append(path.decode('utf-8','replace'))
            fd=self.nextfd; self.nextfd+=1; self.fds[fd]=[content,0]; return R(fd)
        if nr==0x3f:         # read(fd, buf, count)
            st=self.fds.get(x0)
            if st is None: return R(0)
            data,pos=st; chunk=data[pos:pos+x2]
            try: uc.mem_write(x1,chunk)
            except UcError: pass
            st[1]=pos+len(chunk); return R(len(chunk))
        if nr==0x3e:         # lseek(fd, off, whence)  0=SET 1=CUR 2=END
            st=self.fds.get(x0)
            if st is None: return R(0)
            w=x2; st[1]= x1 if w==0 else (st[1]+x1 if w==1 else len(st[0])+x1); return R(st[1])
        if nr==0x50:         # fstat(fd, statbuf) — arm64 struct stat: st_size @ 0x30
            st=self.fds.get(x0)
            sz=len(st[0]) if st else 0
            try:
                uc.mem_write(x1, b"\x00"*0x80)
                uc.mem_write(x1+0x30, struct.pack("<q",sz))       # st_size
                uc.mem_write(x1+0x38, struct.pack("<i",0x1000))   # st_blksize
                uc.mem_write(x1+0x10, struct.pack("<I",0x81a4))   # st_mode reg 0644
            except UcError: pass
            return R(0)
        if nr in (0x4f,0x4e): # newfstatat/statx variants -> success size
            return R(0)
        if nr==0x39: self.fds.pop(x0,None); return R(0)   # close
        if nr==0xde:         # mmap(addr,len,prot,flags,fd,off) -> serve content if fd is ours
            ln=x1; fd=uc.reg_read(UC_ARM64_REG_X0+4); off=uc.reg_read(UC_ARM64_REG_X0+5)
            p=self.alloc(ln or 0x1000)
            st=self.fds.get(fd)
            if st is not None:
                try: uc.mem_write(p, st[0][off:off+ln])
                except UcError: pass
            return R(p)
        if nr==0x116:        # getrandom
            try: uc.mem_write(x0,b"\x11"*min(x1,4096))
            except UcError: pass
            return R(x1)
        return R(0)          # clock/futex/mprotect/write(log)/etc: benign success
    def _tr(self,uc,addr,size,ud):
        self.last.append(addr-base)
        if len(self.last)>40: self.last.pop(0)

if __name__=="__main__":
    e=Emu2(trace=bool(int(os.environ.get("TRACE","0")))); d,f=e.run_init(verbose=False)
    print("init_array: %d/%d ran-to-ret"%(d,d+f))
    uc=e.uc
    for path in _argv or ["../cap.noindex/gt_live/.mss_9b8ed9956d7e60469912dd239a0251f93cd1e80d"]:
        data=open(path,"rb").read(); e.filedata=data; e.opens=[]; e.fds={}; e.nextfd=3
        scratch=base+0x30000000; uc.mem_write(scratch,data)
        desc=scratch+0x100000; uc.mem_write(desc,struct.pack("<IiQ",0,len(data),scratch))
        out=scratch+0x180000; uc.mem_write(out,b"\x00"*32)
        cnt=int(os.environ.get("CNT","30000000"))
        err=e.call(e3.WORKER,(out,desc,1),count=cnt)
        pc=uc.reg_read(UC_ARM64_REG_PC)-base
        plain=e3.read_cxx_string(uc,out)
        pr=sum(1 for b in plain if 32<=b<127)
        print("[%s] pc=0x%x err=%s vt_skips=%d plain=%dB pr=%d%% head=%r"%(
            os.path.basename(path),pc,err,e.stub_hits,len(plain),(pr*100//len(plain)) if plain else 0, plain[:96]))
        if getattr(e,"unhandled",None): print("   unhandled:",dict(e.unhandled))
        if e.trace and err: print("   last PCs:",[hex(x) for x in e.last])
        if e.autoskip: print("   null-blr skips=%d sites=%s"%(len(e.skipped),[hex(a) for a,_ in e.skipped[:30]]))
        if e.syscalls: print("   syscalls:",{hex(k):v for k,v in e.syscalls.items()})
        if e.opens: print("   opened paths:",e.opens)

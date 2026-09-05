import capstone, struct, json
SO='signer/native/libmetasec_ov.so'
f=open(SO,'rb').read()
TEXT_OFF=0x30e00; TEXT_SIZE=0x14ac98; TEXT_ADDR=0x30e00
code=f[TEXT_OFF:TEXT_OFF+TEXT_SIZE]
md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN); md.detail=True
ARM=capstone.arm64
SYS={63:'read',64:'write',65:'readv',66:'writev',57:'close',59:'pipe2',
 198:'socket',199:'socketpair',200:'bind',201:'listen',202:'accept',203:'connect',
 204:'getsockname',205:'getpeername',206:'sendto',207:'recvfrom',208:'setsockopt',
 209:'getsockopt',210:'shutdown',211:'sendmsg',212:'recvmsg',242:'accept4',
 243:'recvmmsg',269:'sendmmsg',73:'ppoll',72:'pselect6',29:'ioctl',25:'fcntl',
 56:'openat',79:'fstatat',80:'fstat',74:'epoll_pwait',21:'epoll_ctl',22:'epoll_create1',
 226:'mprotect',215:'munmap',222:'mmap',96:'set_tid_address',260:'wait4',134:'sigaction',
 129:'kill',101:'nanosleep',113:'clock_gettime',115:'clock_nanosleep',169:'gettimeofday',
 278:'getrandom',117:'ptrace',172:'getpid',178:'gettid',160:'uname',153:'times',
 233:'madvise',214:'brk',122:'sched_setaffinity',123:'sched_getaffinity'}
NET={198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,242,243,269,63,64,65,66,73,72}
def dec1(off):  # decode single insn at file/text offset (aligned)
    try:
        for ins in md.disasm(code[off-TEXT_ADDR:off-TEXT_ADDR+4], off, count=1):
            return ins
    except: pass
    return None
# raw scan svc: (word & 0xFFE0001F)==0xD4000001
svc_offs=[]
n=len(code)
for o in range(0, n-3, 4):
    w=struct.unpack_from('<I',code,o)[0]
    if (w & 0xFFE0001F)==0xD4000001:
        svc_offs.append(TEXT_ADDR+o)
print(f"[*] raw svc sites found: {len(svc_offs)}")
def x8write(ins):
    if not ins or not ins.operands: return None
    m=ins.mnemonic; ops=ins.operands; d=ops[0]
    if d.type!=ARM.ARM64_OP_REG: return None
    if ins.reg_name(d.reg) not in ('x8','w8'): return None
    if m in ('mov','movz') and len(ops)>=2 and ops[1].type==ARM.ARM64_OP_IMM: return ('imm',ops[1].imm&0xffffffff)
    if m=='movn' and len(ops)>=2 and ops[1].type==ARM.ARM64_OP_IMM: return ('imm',(~ops[1].imm)&0xffffffff)
    if m=='orr' and len(ops)>=3 and ops[1].type==ARM.ARM64_OP_REG and ins.reg_name(ops[1].reg) in ('wzr','xzr') and ops[2].type==ARM.ARM64_OP_IMM: return ('imm',ops[2].imm&0xffffffff)
    return ('dyn', f"{m} {ins.op_str}")
sites=[]
for a in svc_offs:
    kind=None; nr=None; ctx=[]
    for j in range(1,31):
        off=a-4*j
        if off<TEXT_ADDR: break
        ins=dec1(off)
        if j<=6 and ins: ctx.append(f"{ins.mnemonic} {ins.op_str}")
        r=x8write(ins)
        if r: kind,nr=r; break
    sites.append((a,kind,nr,ctx))
from collections import Counter
c=Counter()
for a,k,nr,ctx in sites:
    if k=='imm': c[SYS.get(nr,f'#{nr}')]+=1
    elif k=='dyn': c['<dyn>']+=1
    else: c['<none>']+=1
print("[*] histogram:")
for name,cnt in c.most_common(): print(f"    {cnt:4d}  {name}")
print("\n[*] NETWORK svc sites:")
net=[]
for a,k,nr,ctx in sites:
    if k=='imm' and nr in NET:
        nm=SYS.get(nr,f'#{nr}'); print(f"    off=0x{a:x} nr={nr} {nm}"); net.append({'off':a,'nr':nr,'name':nm})
dyns=[(a,nr,ctx) for a,k,nr,ctx in sites if k=='dyn']
print(f"\n[*] <dyn> sites: {len(dyns)} (nr computed at runtime). Show ctx of first 12:")
for a,nr,ctx in dyns[:12]:
    print(f"    off=0x{a:x} x8<-[{nr}]  ctx(bwd): {ctx}")
json.dump({'net':net,'dyn':[a for a,_,_ in dyns],'imm_all':[(a,nr) for a,k,nr,ctx in sites if k=='imm'],'total':len(sites)}, open('scripts/_svc_sites.json','w'))
print("\n[*] saved scripts/_svc_sites.json  total svc:",len(sites))

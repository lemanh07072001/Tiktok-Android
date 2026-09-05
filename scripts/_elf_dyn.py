import struct,sys,re
f=open(sys.argv[1],'rb').read(); end='<'
e_phoff=struct.unpack_from(end+'Q',f,0x20)[0]
e_phnum=struct.unpack_from(end+'H',f,0x38)[0]
e_phentsize=struct.unpack_from(end+'H',f,0x36)[0]
loads=[]; dyn=None
for i in range(e_phnum):
    o=e_phoff+i*e_phentsize
    p_type,p_flags,p_off,p_vaddr,p_paddr,p_filesz,p_memsz,p_align=struct.unpack_from(end+'IIQQQQQQ',f,o)
    if p_type==1: loads.append((p_vaddr,p_off,p_filesz))          # PT_LOAD
    if p_type==2: dyn=(p_off,p_filesz)                            # PT_DYNAMIC
def v2o(v):
    for va,off,sz in loads:
        if va<=v<va+sz: return off+(v-va)
    return None
# parse dynamic
D={}
o,sz=dyn; i=0
while i<sz:
    tag,val=struct.unpack_from(end+'qQ',f,o+i); i+=16
    if tag==0: break
    D.setdefault(tag,val)
SYMTAB=v2o(D[6]); STRTAB=v2o(D[5]); STRSZ=D[10]; SYMENT=D.get(11,24)
# symbol count: prefer DT_GNU_HASH(0x6ffffef5) or DT_HASH(4)
def sym_count():
    if 4 in D:
        h=v2o(D[4]); nchain=struct.unpack_from(end+'I',f,h+4)[0]; return nchain
    if 0x6ffffef5 in D:
        h=v2o(D[0x6ffffef5])
        nbuckets,symoffset,bloom_size,bloom_shift=struct.unpack_from(end+'IIII',f,h)
        bloom=h+16; buckets=bloom+8*bloom_size
        maxi=0
        for b in range(nbuckets):
            bi=struct.unpack_from(end+'I',f,buckets+4*b)[0]
            if bi>maxi: maxi=bi
        if maxi<symoffset: return symoffset
        chain=buckets+4*nbuckets
        idx=maxi
        while True:
            v=struct.unpack_from(end+'I',f,chain+4*(idx-symoffset))[0]
            idx+=1
            if v&1: break
        return idx
    return 0
N=sym_count()
def strn(n):
    e=f.index(b'\x00',STRTAB+n); return f[STRTAB+n:e].decode('latin1')
want=re.compile(r'keylog|ssl_log|SSL_CTX_new|SSL_CTX_set_keylog|SSL_new|SSL_get.*random|SSL_get0|SSL_get_client|EVP_AEAD_CTX_(seal|open|init)|tls13|SSL_provide_quic|SSL_set_quic|quic_method|SSL_do_handshake|SSL_export|SSL_CTX_set_info',re.I)
print(f"dynsym off={SYMTAB:#x} strtab={STRTAB:#x} strsz={STRSZ:#x} nsyms={N}")
defs=0; hits=[]
for k in range(N):
    o=SYMTAB+k*SYMENT
    st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from(end+'IBBHQQ',f,o)
    nm=strn(st_name)
    if st_shndx!=0 and st_value: defs+=1
    if want.search(nm):
        kind=('DEF@0x%x'%st_value) if st_shndx!=0 else 'UNDEF'
        hits.append((nm,kind))
print(f"defined exports: {defs}")
print("=== interesting symbols ===")
for nm,kind in sorted(set(hits)): print(f"  {nm:48} {kind}")

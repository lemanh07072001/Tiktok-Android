import struct,sys,re
f=open(sys.argv[1],'rb').read()
assert f[:4]==b'\x7fELF'
is64=f[4]==2; le=f[5]==1
end='<' if le else '>'
e_shoff=struct.unpack_from(end+'Q',f,0x28)[0]
e_shentsize=struct.unpack_from(end+'H',f,0x3a)[0]
e_shnum=struct.unpack_from(end+'H',f,0x3c)[0]
e_shstrndx=struct.unpack_from(end+'H',f,0x3e)[0]
secs=[]
for i in range(e_shnum):
    off=e_shoff+i*e_shentsize
    name,typ,flags,addr,offset,size,link,info,align,entsize=struct.unpack_from(end+'IIQQQQIIQQ',f,off)
    secs.append(dict(name=name,typ=typ,addr=addr,off=offset,size=size,link=link,entsize=entsize))
shstr=secs[e_shstrndx]
def sname(n): 
    e=f.index(b'\x00',shstr['off']+n); return f[shstr['off']+n:e].decode('latin1')
for s in secs: s['nm']=sname(s['name'])
def parse_syms(symsec):
    strsec=secs[symsec['link']]; base=strsec['off']
    n=symsec['size']//symsec['entsize']; out=[]
    for i in range(n):
        o=symsec['off']+i*symsec['entsize']
        st_name,st_info,st_other,st_shndx,st_value,st_size=struct.unpack_from(end+'IBBHQQ',f,o)
        e=f.index(b'\x00',base+st_name); nm=f[base+st_name:e].decode('latin1')
        out.append((nm,st_value,st_info,st_shndx))
    return out
want=re.compile(r'keylog|ssl_log|SSL_CTX|SSL_new|SSL_get.*random|SSL_get0|EVP_AEAD_CTX_(seal|open|init)|CRYPTO_|tls13|SSL_provide_quic|SSL_set_quic|quic_method|SSL_do_handshake',re.I)
for s in secs:
    if s['nm'] in ('.dynsym','.symtab') and s['entsize']:
        syms=parse_syms(s)
        exp=[x for x in syms if x[3]!=0 and x[1]!=0]  # defined
        print(f"== {s['nm']}: {len(syms)} syms, {len(exp)} defined ==")
        hits=[x for x in syms if want.search(x[0])]
        for nm,val,info,shndx in hits[:80]:
            kind='DEF@0x%x'%val if shndx!=0 else 'UNDEF'
            print(f"   {nm:45} {kind}")

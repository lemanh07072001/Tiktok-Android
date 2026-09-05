import struct,socket,collections,hmac,hashlib
from Crypto.Cipher import AES
F=open('ground-truth/getseed_wire/gs.pcap','rb').read()
linktype=struct.unpack_from('<I',F,20)[0]; off=24; pkts=[]
while off+16<=len(F):
    ts_s,ts_u,incl,orig=struct.unpack_from('<IIII',F,off); off+=16
    pkts.append((ts_s+ts_u/1e6,F[off:off+incl])); off+=incl
MY='192.168.1.204'
def parse(d):
    if linktype==1: et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    else: l3=d; et=0x0800 if (d[0]>>4)==4 else 0x86dd
    if et==0x0800: ihl=(l3[0]&0xf)*4; proto=l3[9]; src=socket.inet_ntoa(l3[12:16]); dst=socket.inet_ntoa(l3[16:20]); l4=l3[ihl:]
    elif et==0x86dd: proto=l3[6]; src=socket.inet_ntop(socket.AF_INET6,l3[8:24]); dst=socket.inet_ntop(socket.AF_INET6,l3[24:40]); l4=l3[40:]
    else: return None
    if proto==17: sp,dp=struct.unpack_from('>HH',l4,0); ln=struct.unpack_from('>H',l4,4)[0]; return('udp',src,sp,dst,dp,l4[8:ln])
    return None
# gather client->server UDP:443 datagrams per remote ip
cli=collections.OrderedDict()
for t,d in pkts:
    r=parse(d)
    if not r: continue
    proto,src,sp,dst,dp,pay=r
    if src==MY and dp==443 and pay:
        cli.setdefault(dst,[]).append(pay)

SALTS={0xff00001d:bytes.fromhex('afbfec289993d24c9e9786f19c6111e04390a899'),
       0x00000001:bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
       0xff00001b:bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502'),
       0xff00001c:bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')}
def hkdf_extract(salt,ikm): return hmac.new(salt,ikm,hashlib.sha256).digest()
def hkdf_expand_label(secret,label,length):
    lab=b'tls13 '+label
    info=struct.pack('>H',length)+bytes([len(lab)])+lab+b'\x00'
    out=b''; t=b''; i=1
    while len(out)<length:
        t=hmac.new(secret,t+info+bytes([i]),hashlib.sha256).digest(); out+=t; i+=1
    return out[:length]
def rd_varint(b,p):
    v=b[p]; pre=v>>6; l=1<<pre; val=v&0x3f
    for j in range(1,l): val=(val<<8)|b[p+j]
    return val,p+l
def decrypt_initial(dg,salt):
    # returns crypto (offset,data) list or None
    if not dg or not (dg[0]&0x80): return None
    ver=struct.unpack_from('>I',dg,1)[0]
    if ver not in SALTS: salt2=salt
    else: salt2=SALTS[ver]
    p=5; dcil=dg[p]; p+=1; dcid=dg[p:p+dcil]; p+=dcil
    scil=dg[p]; p+=1; scid=dg[p:p+scil]; p+=scil
    # long header type: Initial has token
    ptype=(dg[0]&0x30)>>4
    if ptype!=0: return None  # only Initial
    tl,p=rd_varint(dg,p); p+=tl  # token
    length,p=rd_varint(dg,p)
    pn_off=p
    isec=hkdf_extract(salt2,dcid)
    csec=hkdf_expand_label(isec,b'client in',32)
    key=hkdf_expand_label(csec,b'quic key',16)
    iv=hkdf_expand_label(csec,b'quic iv',12)
    hp=hkdf_expand_label(csec,b'quic hp',16)
    sample=dg[pn_off+4:pn_off+4+16]
    mask=AES.new(hp,AES.MODE_ECB).encrypt(sample)
    fb=dg[0]^(mask[0]&0x0f)
    pnlen=(fb&0x03)+1
    pnb=bytes(dg[pn_off+i]^mask[1+i] for i in range(pnlen))
    pn=int.from_bytes(pnb,'big')
    hdr=bytearray(dg[:pn_off+pnlen]); hdr[0]=fb
    for i in range(pnlen): hdr[pn_off+i]=pnb[i]
    ct=dg[pn_off+pnlen:pn_off+length]  # length covers pn+payload
    nonce=bytes(iv[i]^(pn.to_bytes(12,'big')[i]) for i in range(12))
    try:
        pt=AES.new(key,AES.MODE_GCM,nonce=nonce).update(bytes(hdr)) or None
    except: pass
    c=AES.new(key,AES.MODE_GCM,nonce=nonce); c.update(bytes(hdr))
    try: pt=c.decrypt_and_verify(ct[:-16],ct[-16:])
    except Exception as e: return ('ERR',str(e))
    # parse frames
    frames=[]; i=0
    while i<len(pt):
        ft,i=rd_varint(pt,i)
        if ft==0x00: continue
        if ft==0x01: continue
        if ft==0x02 or ft==0x03:
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); _,i=rd_varint(pt,i)
            if ft==0x03: _,i=rd_varint(pt,i)
            continue
        if ft==0x06:
            offv,i=rd_varint(pt,i); ln,i=rd_varint(pt,i); frames.append((offv,pt[i:i+ln])); i+=ln; continue
        break
    return frames
def sni_from_ch(b):
    try:
        p=0
        if b[p]!=0x01: return None
        p+=4; p+=2; p+=32
        sidlen=b[p]; p+=1+sidlen
        cslen=int.from_bytes(b[p:p+2],'big'); p+=2+cslen
        cl=b[p]; p+=1+cl
        extlen=int.from_bytes(b[p:p+2],'big'); p+=2; end=p+extlen
        while p+4<=end:
            et=int.from_bytes(b[p:p+2],'big'); el=int.from_bytes(b[p+2:p+4],'big'); p+=4
            if et==0x0000:
                q=p+2; q+=1; nl=int.from_bytes(b[q:q+2],'big'); q+=2
                return b[q:q+nl].decode('latin1')
            p+=el
    except: return None
def split_coalesced(dg):
    # yield each QUIC packet in a UDP datagram (long-header only for Initial hunt)
    out=[]; p=0
    while p<len(dg) and (dg[p]&0x80):
        # need to compute packet len to advance; reuse Initial parse crudely
        start=p; ver=struct.unpack_from('>I',dg,p+1)[0]; q=p+5
        dcil=dg[q]; q+=1+dcil; scil=dg[q]; q+=1+scil
        ptype=(dg[p]&0x30)>>4
        if ptype==0:
            tl,q=rd_varint(dg,q); q+=tl
        length,q=rd_varint(dg,q)
        out.append(dg[start:q+length]); p=q+length
    if not out: out=[dg]
    return out
print("=== IETF QUIC flows -> SNI (from decrypted Initial) ===")
for rip,dgs in cli.items():
    if not dgs or not (dgs[0][0]&0x80): continue
    crypto=[]
    for dg in dgs[:6]:
        for pk in split_coalesced(dg):
            r=decrypt_initial(pk,None)
            if isinstance(r,tuple) and r and r[0]=='ERR': continue
            if r:
                for o,dd in r: crypto.append((o,dd))
    if not crypto: 
        print(f"  {rip:20} (no Initial CRYPTO decrypted)"); continue
    mx=max(o+len(d) for o,d in crypto); buf=bytearray(mx)
    for o,d in crypto: buf[o:o+len(d)]=d
    sni=sni_from_ch(bytes(buf))
    print(f"  {rip:20} SNI={sni}")

import struct,socket,collections
F=open('ground-truth/getseed_wire/gs.pcap','rb').read()
linktype=struct.unpack_from('<I',F,20)[0]; off=24; pkts=[]
while off+16<=len(F):
    ts_s,ts_u,incl,orig=struct.unpack_from('<IIII',F,off); off+=16
    pkts.append((ts_s+ts_u/1e6,F[off:off+incl])); off+=incl
def parse(d):
    if linktype==1: et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    else: l3=d; et=0x0800 if (d[0]>>4)==4 else 0x86dd
    if et==0x0800: ihl=(l3[0]&0xf)*4; proto=l3[9]; src=socket.inet_ntoa(l3[12:16]); dst=socket.inet_ntoa(l3[16:20]); l4=l3[ihl:]
    elif et==0x86dd: proto=l3[6]; src=socket.inet_ntop(socket.AF_INET6,l3[8:24]); dst=socket.inet_ntop(socket.AF_INET6,l3[24:40]); l4=l3[40:]
    else: return None
    if proto==6: sport,dport=struct.unpack_from('>HH',l4,0); doff=(l4[12]>>4)*4; return('tcp',src,sport,dst,dport,l4[doff:])
    if proto==17: sport,dport=struct.unpack_from('>HH',l4,0); ln=struct.unpack_from('>H',l4,4)[0]; return('udp',src,sport,dst,dport,l4[8:ln])
    return None
MY='192.168.1.204'
# reassemble first client bytes per tcp flow
tcpbuf=collections.OrderedDict()
for t,d in pkts:
    r=parse(d)
    if not r: continue
    proto,src,sport,dst,dport,pay=r
    if proto!='tcp' or src!=MY or not pay: continue
    key=(dst,dport,sport)
    tcpbuf.setdefault(key,b'')
    if len(tcpbuf[key])<2048: tcpbuf[key]+=pay
def sni_from_ch(b):
    try:
        if b[0]!=0x16: return None
        # TLS record(s): may span; assume b is handshake stream after record header
        # skip 5-byte record header
        p=5
        if b[p]!=0x01: return None  # ClientHello
        hlen=int.from_bytes(b[p+1:p+4],'big'); p+=4
        p+=2  # client version
        p+=32 # random
        sidlen=b[p]; p+=1+sidlen
        cslen=int.from_bytes(b[p:p+2],'big'); p+=2+cslen
        complen=b[p]; p+=1+complen
        extlen=int.from_bytes(b[p:p+2],'big'); p+=2
        end=p+extlen
        while p+4<=end:
            et=int.from_bytes(b[p:p+2],'big'); el=int.from_bytes(b[p+2:p+4],'big'); p+=4
            if et==0x0000:
                # SNI ext
                q=p+2; nt=b[q]; nl=int.from_bytes(b[q+1:q+3],'big'); q+=3
                return b[q:q+nl].decode('latin1')
            p+=el
    except: return None
    return None
print("=== TCP:443 flows -> SNI ===")
byip=collections.OrderedDict()
for (dst,dport,sport),b in tcpbuf.items():
    sni=sni_from_ch(b)
    byip.setdefault((dst,dport),set())
    if sni: byip[(dst,dport)].add(sni)
for (dst,dport),snis in byip.items():
    print(f"  {dst:22} :{dport}  SNI={sorted(snis) if snis else '(none/parsefail)'}")

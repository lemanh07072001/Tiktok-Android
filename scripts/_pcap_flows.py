import struct,socket,collections
F=open('ground-truth/getseed_wire/gs.pcap','rb').read()
magic=struct.unpack_from('<I',F,0)[0]
le = magic in (0xa1b2c3d4,0xa1b23c4d)
nano = magic in (0xa1b23c4d,0x4d3cb2a1)
E='<' if le else '>'
linktype=struct.unpack_from(E+'I',F,20)[0]
print(f"magic=0x{magic:08x} le={le} nano={nano} linktype={linktype} size={len(F)}")
off=24
pkts=[]
while off+16<=len(F):
    ts_s,ts_u,incl,orig=struct.unpack_from(E+'IIII',F,off); off+=16
    data=F[off:off+incl]; off+=incl
    pkts.append((ts_s+ts_u/(1e9 if nano else 1e6),data))
print("packets:",len(pkts))
def parse_l3(d):
    # returns (proto, src, sport, dst, dport, payload) or None
    if linktype==1:
        if len(d)<14: return None
        et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    elif linktype==101: # raw IP
        l3=d; et=0x0800 if (d[0]>>4)==4 else 0x86dd
    elif linktype==113: # linux cooked
        if len(d)<16: return None
        et=struct.unpack_from('>H',d,14)[0]; l3=d[16:]
    else:
        l3=d; et=0x0800 if d and (d[0]>>4)==4 else 0x86dd
    if et==0x0800:
        if len(l3)<20: return None
        ihl=(l3[0]&0xf)*4; proto=l3[9]
        src=socket.inet_ntoa(l3[12:16]); dst=socket.inet_ntoa(l3[16:20])
        l4=l3[ihl:]
    elif et==0x86dd:
        if len(l3)<40: return None
        proto=l3[6]
        src=socket.inet_ntop(socket.AF_INET6,l3[8:24]); dst=socket.inet_ntop(socket.AF_INET6,l3[24:40])
        l4=l3[40:]
    else: return None
    if proto==6: # tcp
        if len(l4)<20: return None
        sport,dport=struct.unpack_from('>HH',l4,0); doff=(l4[12]>>4)*4
        return ('tcp',src,sport,dst,dport,l4[doff:])
    if proto==17: # udp
        if len(l4)<8: return None
        sport,dport=struct.unpack_from('>HH',l4,0); ln=struct.unpack_from('>H',l4,4)[0]
        return ('udp',src,sport,dst,dport,l4[8:ln] if ln>=8 else l4[8:])
    return None
MYIP='192.168.1.204'
flows=collections.OrderedDict()  # (proto,rip,rport)-> {tx,rx,firstpay,t0,pkts}
for t,d in pkts:
    r=parse_l3(d)
    if not r: continue
    proto,src,sport,dst,dport,pay=r
    # orient: remote = the non-MYIP side
    if src==MYIP: rip,rport,dirn=dst,dport,'tx'
    elif dst==MYIP: rip,rport,dirn=src,sport,'rx'
    else: continue
    key=(proto,rip,rport)
    fl=flows.setdefault(key,{'tx':0,'rx':0,'txb':0,'rxb':0,'firstpay':None,'t0':t,'firstpaydir':None})
    fl[dirn]+=1; fl[dirn+'b']+=len(pay)
    if pay and fl['firstpay'] is None and dirn=='tx':
        fl['firstpay']=pay[:16]; fl['firstpaydir']='tx'
# report: focus on port 443 and non-standard
print("\n=== flows (remote:port) sorted by bytes ===")
def tls_sig(p):
    if not p: return 'NOPAY'
    if p[0]==0x16 and p[1]==0x03: return 'TLS-handshake'
    if p[0] in (0xc0,0xc1,0xc2,0xc3,0xcf) or (p[0]&0x80): return 'QUIC?'
    return 'NON-TLS'
rows=[]
for (proto,rip,rport),fl in flows.items():
    tot=fl['txb']+fl['rxb']
    fp=fl['firstpay']
    rows.append((tot,proto,rip,rport,fl['tx'],fl['rx'],fl['txb'],fl['rxb'],tls_sig(fp),fp.hex() if fp else ''))
rows.sort(reverse=True)
for tot,proto,rip,rport,tx,rx,txb,rxb,sig,fph in rows:
    print(f"  {proto} {rip:22} :{rport:<5} tx={tx:4}/{txb:7}B rx={rx:4}/{rxb:8}B  first={sig:14} {fph}")

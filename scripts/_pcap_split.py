import struct,socket,collections
F=open('ground-truth/getseed_wire/gs.pcap','rb').read()
E='<'; linktype=struct.unpack_from('<I',F,20)[0]
off=24; pkts=[]
while off+16<=len(F):
    ts_s,ts_u,incl,orig=struct.unpack_from('<IIII',F,off); off+=16
    pkts.append((ts_s+ts_u/1e6,F[off:off+incl])); off+=incl
def parse(d):
    if linktype==1:
        et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    else:
        l3=d; et=0x0800 if (d[0]>>4)==4 else 0x86dd
    if et==0x0800:
        ihl=(l3[0]&0xf)*4; proto=l3[9]; src=socket.inet_ntoa(l3[12:16]); dst=socket.inet_ntoa(l3[16:20]); l4=l3[ihl:]
    elif et==0x86dd:
        proto=l3[6]; src=socket.inet_ntop(socket.AF_INET6,l3[8:24]); dst=socket.inet_ntop(socket.AF_INET6,l3[24:40]); l4=l3[40:]
    else: return None
    if proto==6:
        sport,dport=struct.unpack_from('>HH',l4,0); doff=(l4[12]>>4)*4; return('tcp',src,sport,dst,dport,l4[doff:])
    if proto==17:
        sport,dport=struct.unpack_from('>HH',l4,0); ln=struct.unpack_from('>H',l4,4)[0]; return('udp',src,sport,dst,dport,l4[8:ln])
    return None
MY='192.168.1.204'
t_base=pkts[0][0]
# split by full tuple, remote = 139.177.243.248 (ByteDance non-TLS)
TARGET='139.177.243.248'
socks=collections.OrderedDict()
for t,d in pkts:
    r=parse(d)
    if not r: continue
    proto,src,sport,dst,dport,pay=r
    if TARGET not in (src,dst): continue
    if src==MY: lport,dirn=sport,'tx'
    elif dst==MY: lport,dirn=dport,'rx'
    else: continue
    key=(proto,lport)
    s=socks.setdefault(key,{'t0':t,'tl':t,'tx':0,'rx':0,'txb':0,'rxb':0,'first':[]})
    s[dirn]+=1; s[dirn+'b']+=len(pay); s['tl']=t
    if len(s['first'])<4 and pay:
        s['first'].append((dirn,round(t-t_base,2),len(pay),pay[:40].hex()))
print(f"=== sub-sockets to {TARGET} (ByteDance proprietary), by local port ===")
for (proto,lport),s in sorted(socks.items(), key=lambda x:x[1]['t0']):
    dur=round(s['tl']-s['t0'],2); t0=round(s['t0']-t_base,2)
    print(f"\n {proto} lport={lport} t0={t0}s dur={dur}s tx={s['tx']}/{s['txb']}B rx={s['rx']}/{s['rxb']}B")
    for dirn,dt,ln,h in s['first']:
        print(f"    {dirn} +{dt}s {ln}B {h}")

import struct,socket,collections
F=open('ground-truth/getseed_wire/gs.pcap','rb').read()
linktype=struct.unpack_from('<I',F,20)[0]; off=24; pkts=[]
while off+16<=len(F):
    ts_s,ts_u,incl,orig=struct.unpack_from('<IIII',F,off); off+=16
    pkts.append((ts_s+ts_u/1e6,F[off:off+incl])); off+=incl
t0=pkts[0][0]
def parse(d):
    if linktype==1: et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    else: l3=d; et=0x0800 if (d[0]>>4)==4 else 0x86dd
    if et==0x0800: ihl=(l3[0]&0xf)*4; proto=l3[9]; src=socket.inet_ntoa(l3[12:16]); dst=socket.inet_ntoa(l3[16:20]); l4=l3[ihl:]
    elif et==0x86dd: proto=l3[6]; src=socket.inet_ntop(socket.AF_INET6,l3[8:24]); dst=socket.inet_ntop(socket.AF_INET6,l3[24:40]); l4=l3[40:]
    else: return None
    if proto==6: sp,dp=struct.unpack_from('>HH',l4,0); doff=(l4[12]>>4)*4; return('tcp',src,sp,dst,dp,l4[doff:])
    if proto==17: sp,dp=struct.unpack_from('>HH',l4,0); ln=struct.unpack_from('>H',l4,4)[0]; return('udp',src,sp,dst,dp,l4[8:ln])
    return None
MY='192.168.1.204'
flows=collections.OrderedDict()  # (proto,rip,rport,lport)->stats
for t,d in pkts:
    r=parse(d)
    if not r: continue
    proto,src,sp,dst,dp,pay=r
    if src==MY: rip,rport,lport,dr=dst,dp,sp,'tx'
    elif dst==MY: rip,rport,lport,dr=src,sp,dp,'rx'
    else: continue
    k=(proto,rip,rport,lport)
    s=flows.setdefault(k,{'t0':t-t0,'tx':0,'txb':0,'rx':0,'rxb':0,'first':None,'firstT':None})
    if dr=='tx':
        s['tx']+=1; s['txb']+=len(pay)
        if s['first'] is None and pay: s['first']=pay[:24].hex(); s['firstT']=t-t0
    else:
        s['rx']+=1; s['rxb']+=len(pay)
# aggregate by (proto,rip,rport) but show socket count
agg=collections.OrderedDict()
for (proto,rip,rport,lport),s in flows.items():
    k=(proto,rip,rport); a=agg.setdefault(k,{'socks':0,'t0':s['t0'],'txb':0,'rxb':0,'first':s['first'],'firstT':s['firstT']})
    a['socks']+=1; a['txb']+=s['txb']; a['rxb']+=s['rxb']
    a['t0']=min(a['t0'],s['t0'])
    if s['firstT'] is not None and (a['firstT'] is None or s['firstT']<a['firstT']):
        a['firstT']=s['firstT']; a['first']=s['first']
print(f"{'proto':5} {'remote':24} {'port':5} {'sk':>2} {'t0':>6} {'txB':>9} {'rxB':>9}  first-client-bytes")
for (proto,rip,rport),a in sorted(agg.items(),key=lambda x:x[1]['t0']):
    fb=a['first'] or ''
    tag=''
    if fb.startswith('1603'): tag='TLS'
    elif fb and int(fb[:2],16)&0x80: tag='QUIC-ietf?'
    elif fb[:2] in ('0d','0c','08','09','0a','0b'): tag='gQUIC?'
    elif fb[:8]=='43484c4f': tag='CHLO'
    print(f"{proto:5} {rip:24} {rport:5} {a['socks']:>2} {a['t0']:>6.2f} {a['txb']:>9} {a['rxb']:>9}  {fb[:20]} {tag}")

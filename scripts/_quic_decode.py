#!/usr/bin/env python3
# QUIC 1-RTT decoder: proves the extracted BoringSSL traffic secrets decrypt the
# captured wire. Inputs: gs2.pcap (tcpdump) + keylog2.txt (NSS keylog from Frida).
# Derives 1-RTT key/iv/hp from CLIENT/SERVER_TRAFFIC_SECRET_0 (RFC 9001), removes
# header protection, AEAD-opens short-header packets, reassembles STREAM frames,
# and dumps the HTTP/3 frame layer. Secrets are NEVER printed.
import struct, socket, collections, hmac, hashlib, sys, os
from Crypto.Cipher import AES
try: from Crypto.Cipher import ChaCha20
except Exception: ChaCha20=None

PCAP = sys.argv[1] if len(sys.argv)>1 else 'ground-truth/getseed_wire/gs2.pcap'
KEYLOG = sys.argv[2] if len(sys.argv)>2 else 'ground-truth/getseed_wire/keylog2.txt'
WANT = sys.argv[3] if len(sys.argv)>3 else 'api22-normal'   # SNI substring filter ('*' = all)
OUTDIR = 'ground-truth/getseed_wire/decoded'
MY = '192.168.1.204'
os.makedirs(OUTDIR, exist_ok=True)

# ---------- pcap ----------
F=open(PCAP,'rb').read()
magic=struct.unpack_from('<I',F,0)[0]
linktype=struct.unpack_from('<I',F,20)[0]; off=24; pkts=[]
while off+16<=len(F):
    ts_s,ts_u,incl,orig=struct.unpack_from('<IIII',F,off); off+=16
    pkts.append(F[off:off+incl]); off+=incl
def parse_udp(d):
    if linktype==1: et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    elif linktype==101: l3=d; et=0x0800 if (d[0]>>4)==4 else 0x86dd
    else: et=struct.unpack_from('>H',d,12)[0]; l3=d[14:]
    if et==0x0800: ihl=(l3[0]&0xf)*4; proto=l3[9]; src=socket.inet_ntoa(l3[12:16]); dst=socket.inet_ntoa(l3[16:20]); l4=l3[ihl:]
    elif et==0x86dd: proto=l3[6]; src=socket.inet_ntop(socket.AF_INET6,l3[8:24]); dst=socket.inet_ntop(socket.AF_INET6,l3[24:40]); l4=l3[40:]
    else: return None
    if proto!=17: return None
    sp,dp=struct.unpack_from('>HH',l4,0); ln=struct.unpack_from('>H',l4,4)[0]
    return (src,sp,dst,dp,l4[8:ln])

# ---------- crypto helpers ----------
SALTS={0xff00001d:bytes.fromhex('afbfec289993d24c9e9786f19c6111e04390a899'),
       0x00000001:bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
       0xff00001b:bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502'),
       0xff00001c:bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')}
def hkdf_expand_label(secret,label,length,hfun):
    lab=b'tls13 '+label
    info=struct.pack('>H',length)+bytes([len(lab)])+lab+b'\x00'
    out=b''; t=b''; i=1
    hl=hfun().digest_size
    while len(out)<length:
        t=hmac.new(secret,t+info+bytes([i]),hfun).digest(); out+=t; i+=1
    return out[:length]
def rd_varint(b,p):
    v=b[p]; pre=v>>6; l=1<<pre; val=v&0x3f
    for j in range(1,l): val=(val<<8)|b[p+j]
    return val,p+l

# ciphers: (name, keylen, hashfn, aead_ctor)
def aes_gcm_open(key,nonce,ct,aad):
    c=AES.new(key,AES.MODE_GCM,nonce=nonce); c.update(aad)
    return c.decrypt_and_verify(ct[:-16],ct[-16:])
CIPHERS=[('AES128GCM',16,hashlib.sha256,'aes'),
         ('CHACHA20',32,hashlib.sha256,'chacha'),
         ('AES256GCM',32,hashlib.sha384,'aes')]
def hp_mask(kind,hp,sample):
    if kind=='aes':
        return AES.new(hp,AES.MODE_ECB).encrypt(sample[:16])
    else:
        if ChaCha20 is None: return None
        ctr=int.from_bytes(sample[0:4],'little'); nonce=sample[4:16]
        c=ChaCha20.new(key=hp,nonce=nonce); c.seek(ctr*64)
        return c.encrypt(b'\x00'*5)
def aead_open(kind,key,nonce,ct,aad):
    if kind=='aes': return aes_gcm_open(key,nonce,ct,aad)
    from Crypto.Cipher import ChaCha20_Poly1305
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce); c.update(aad)
    return c.decrypt_and_verify(ct[:-16],ct[-16:])
def decode_pn(trunc,nbits,largest):
    win=1<<nbits; hwin=win//2; mask=win-1
    cand=(largest+1 & ~mask)|trunc
    if cand<=(largest+1)-hwin and cand<(1<<62)-win: return cand+win
    if cand>(largest+1)+hwin and cand>=win: return cand-win
    return cand

# ---------- Initial decrypt (for SNI + CIDs + client_random) ----------
def split_coalesced(dg):
    out=[]; p=0
    while p<len(dg) and (dg[p]&0x80):
        start=p; q=p+5; dcil=dg[q]; q+=1+dcil; scil=dg[q]; q+=1+scil
        ptype=(dg[p]&0x30)>>4
        if ptype==0: tl,q=rd_varint(dg,q); q+=tl
        length,q=rd_varint(dg,q); out.append(dg[start:q+length]); p=q+length
    if not out: out=[dg]
    return out
def parse_long_ids(pk):
    ver=struct.unpack_from('>I',pk,1)[0]; q=5
    dcil=pk[q]; q+=1; dcid=pk[q:q+dcil]; q+=dcil
    scil=pk[q]; q+=1; scid=pk[q:q+scil]; q+=scil
    return ver,dcid,scid
def decrypt_initial(pk):
    if not (pk[0]&0x80) or ((pk[0]&0x30)>>4)!=0: return None
    ver,dcid,scid=parse_long_ids(pk); q=5+1+len(dcid)+1+len(scid)
    tl,q=rd_varint(pk,q); q+=tl; length,q=rd_varint(pk,q); pn_off=q
    salt=SALTS.get(ver,SALTS[0xff00001d])
    isec=hmac.new(salt,dcid,hashlib.sha256).digest()
    csec=hkdf_expand_label(isec,b'client in',32,hashlib.sha256)
    key=hkdf_expand_label(csec,b'quic key',16,hashlib.sha256)
    iv=hkdf_expand_label(csec,b'quic iv',12,hashlib.sha256)
    hp=hkdf_expand_label(csec,b'quic hp',16,hashlib.sha256)
    sample=pk[pn_off+4:pn_off+20]; mask=AES.new(hp,AES.MODE_ECB).encrypt(sample)
    fb=pk[0]^(mask[0]&0x0f); pnlen=(fb&3)+1
    pnb=bytes(pk[pn_off+i]^mask[1+i] for i in range(pnlen)); pn=int.from_bytes(pnb,'big')
    hdr=bytearray(pk[:pn_off+pnlen]); hdr[0]=fb
    for i in range(pnlen): hdr[pn_off+i]=pnb[i]
    ct=pk[pn_off+pnlen:pn_off+length]
    nonce=bytes(iv[i]^pn.to_bytes(12,'big')[i] for i in range(12))
    try: pt=aes_gcm_open(key,nonce,ct,bytes(hdr))
    except Exception: return None
    frames=[]; i=0
    while i<len(pt):
        ft,i=rd_varint(pt,i)
        if ft in (0x00,0x01): continue
        if ft in (0x02,0x03):
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); n,i=rd_varint(pt,i)
            for _ in range(0): pass
            _,i=rd_varint(pt,i)
            if ft==0x03: _,i=rd_varint(pt,i)
            continue
        if ft==0x06:
            o,i=rd_varint(pt,i); ln,i=rd_varint(pt,i); frames.append((o,pt[i:i+ln])); i+=ln; continue
        break
    return {'ver':ver,'dcid':dcid,'scid':scid,'crypto':frames}
def sni_and_random(chbuf):
    b=chbuf; sni=None; crand=None
    try:
        p=0
        if b[p]!=0x01: return None,None
        p+=4; p+=2; crand=b[p:p+32]; p+=32
        sidlen=b[p]; p+=1+sidlen
        cslen=int.from_bytes(b[p:p+2],'big'); p+=2+cslen
        cl=b[p]; p+=1+cl
        extlen=int.from_bytes(b[p:p+2],'big'); p+=2; end=p+extlen
        while p+4<=end:
            et=int.from_bytes(b[p:p+2],'big'); el=int.from_bytes(b[p+2:p+4],'big'); p+=4
            if et==0x0000:
                q=p+2; q+=1; nl=int.from_bytes(b[q:q+2],'big'); q+=2; sni=b[q:q+nl].decode('latin1')
            p+=el
    except Exception: pass
    return sni,crand

# ---------- keylog ----------
KL=collections.defaultdict(dict)
for line in open(KEYLOG,'r',encoding='utf-8',errors='replace'):
    parts=line.split()
    if len(parts)==3:
        KL[parts[1].lower()][parts[0]]=bytes.fromhex(parts[2])

# ---------- group datagrams into connections by (lport,rip,rport) ----------
conns=collections.OrderedDict()
for d in pkts:
    r=parse_udp(d)
    if not r: continue
    src,sp,dst,dp,pay=r
    if not pay: continue
    if src==MY:  # client->server
        key=(sp,dst,dp); dirn='c2s'
    elif dst==MY:  # server->client
        key=(dp,src,sp); dirn='s2c'
    else: continue
    conns.setdefault(key,[]).append((dirn,pay))

print(f"[*] pcap={PCAP} pkts={len(pkts)} udp-quic-conns={len(conns)} keylog-conns={len(KL)}")

# ---------- per-connection processing ----------
def stream_frame_parse(pt, streams):
    i=0; L=len(pt); nframes=0
    while i<L:
        ft,i=rd_varint(pt,i); nframes+=1
        if ft==0x00: continue                     # PADDING
        if ft==0x01: continue                     # PING
        if ft in (0x02,0x03):                     # ACK
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); rc,i=rd_varint(pt,i); _,i=rd_varint(pt,i)
            for _ in range(rc): _,i=rd_varint(pt,i); _,i=rd_varint(pt,i)
            if ft==0x03:
                for _ in range(3): _,i=rd_varint(pt,i)
            continue
        if ft==0x04:                              # RESET_STREAM
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); continue
        if ft==0x05:                              # STOP_SENDING
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); continue
        if ft==0x06:                              # CRYPTO
            o,i=rd_varint(pt,i); ln,i=rd_varint(pt,i); i+=ln; continue
        if ft==0x07:                              # NEW_TOKEN
            ln,i=rd_varint(pt,i); i+=ln; continue
        if 0x08<=ft<=0x0f:                        # STREAM
            sid,i=rd_varint(pt,i)
            off=0
            if ft&0x04: off,i=rd_varint(pt,i)
            if ft&0x02: ln,i=rd_varint(pt,i)
            else: ln=L-i
            data=pt[i:i+ln]; i+=ln
            streams.setdefault(sid,{})[off]=data
            continue
        if ft==0x10: _,i=rd_varint(pt,i); continue                     # MAX_DATA
        if ft==0x11: _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); continue# MAX_STREAM_DATA
        if ft in (0x12,0x13): _,i=rd_varint(pt,i); continue            # MAX_STREAMS
        if ft==0x14: _,i=rd_varint(pt,i); continue                     # DATA_BLOCKED
        if ft==0x15: _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); continue# STREAM_DATA_BLOCKED
        if ft in (0x16,0x17): _,i=rd_varint(pt,i); continue            # STREAMS_BLOCKED
        if ft==0x18:                              # NEW_CONNECTION_ID
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); cl=pt[i]; i+=1; i+=cl; i+=16; continue
        if ft==0x19: _,i=rd_varint(pt,i); continue                     # RETIRE_CONNECTION_ID
        if ft==0x1a: i+=8; ln,i=rd_varint(pt,i); i+=ln; continue       # PATH_CHALLENGE (8B)+? (simplified)
        if ft==0x1b: i+=8; continue                                    # PATH_RESPONSE
        if ft in (0x1c,):                          # CONNECTION_CLOSE (transport)
            _,i=rd_varint(pt,i); _,i=rd_varint(pt,i); ln,i=rd_varint(pt,i); i+=ln; continue
        if ft in (0x1d,):                          # CONNECTION_CLOSE (app)
            _,i=rd_varint(pt,i); ln,i=rd_varint(pt,i); i+=ln; continue
        if ft==0x1e: continue                     # HANDSHAKE_DONE
        # unknown -> stop this packet
        break
    return nframes

def assemble(streams):
    out={}
    for sid,chunks in streams.items():
        buf=bytearray()
        for o in sorted(chunks):
            if o>len(buf): buf.extend(b'\x00'*(o-len(buf)))
            buf[o:o+len(chunks[o])]=chunks[o]
        out[sid]=bytes(buf)
    return out

H3NAME={0x00:'DATA',0x01:'HEADERS',0x03:'CANCEL_PUSH',0x04:'SETTINGS',0x05:'PUSH_PROMISE',0x07:'GOAWAY',0x0d:'MAX_PUSH_ID'}
def h3_frames(sid,data):
    # returns (uni_stream_type_or_None, [(ftype,body),...])
    i=0; L=len(data); uni=(sid&0x02)!=0; utype=None
    if uni and L>0: utype,i=rd_varint(data,i)
    frames=[]
    while i<L:
        try: ft,i=rd_varint(data,i); fl,i=rd_varint(data,i)
        except Exception: break
        frames.append((ft,data[i:i+fl])); i+=fl
    return utype,frames

try:
    from pylsqpack import Decoder as QDecoder
except Exception:
    QDecoder=None

targets=[]
for key,dgrams in conns.items():
    lport,rip,rport=key
    # collect initials + short-header packets
    cli_scid=None; srv_scid=None; sni=None; crand=None
    ch=collections.defaultdict(bytes)
    shorts=[]  # (dirn, pkt)
    for dirn,dg in dgrams:
        if dg[0]&0x80:
            for pk in split_coalesced(dg):
                if not (pk[0]&0x80): shorts.append((dirn,pk)); continue
                ptype=(pk[0]&0x30)>>4
                ver,dcid,scid=parse_long_ids(pk)
                if dirn=='c2s' and ptype==0 and cli_scid is None: cli_scid=scid
                if dirn=='s2c' and ptype==0 and srv_scid is None: srv_scid=scid
                if ptype==0:
                    r=decrypt_initial(pk)
                    if r and dirn=='c2s':
                        for o,dd in r['crypto']:
                            ch[o]=dd
        else:
            shorts.append((dirn,dg))
    if ch:
        mx=max(o+len(d) for o,d in ch.items()); buf=bytearray(mx)
        for o,d in ch.items(): buf[o:o+len(d)]=d
        sni,crand=sni_and_random(bytes(buf))
    targets.append((key,sni,crand,cli_scid,srv_scid,shorts))

print("\n=== connections ===")
for key,sni,crand,cli_scid,srv_scid,shorts in targets:
    lport,rip,rport=key
    haskeys = crand and crand.hex() in KL
    print(f"  lport={lport:<6} {rip}:{rport}  SNI={sni}  short_pkts={len(shorts)}  crand={'yes' if crand else 'no'}  keylog={'YES' if haskeys else 'no'}")

# ---------- decrypt target connection(s) ----------
def try_derive(secret):
    for name,klen,hfun,kind in CIPHERS:
        if kind=='chacha' and ChaCha20 is None: continue
        key=hkdf_expand_label(secret,b'quic key',klen,hfun)
        iv=hkdf_expand_label(secret,b'quic iv',12,hfun)
        hp=hkdf_expand_label(secret,b'quic hp',klen,hfun)
        yield name,kind,key,iv,hp

for key,sni,crand,cli_scid,srv_scid,shorts in targets:
    if WANT!='*' and (not sni or WANT not in sni): continue
    if not crand or crand.hex() not in KL:
        print(f"\n[!] {sni}: no keylog for client_random"); continue
    secs=KL[crand.hex()]
    csec=secs.get('CLIENT_TRAFFIC_SECRET_0'); ssec=secs.get('SERVER_TRAFFIC_SECRET_0')
    print(f"\n=== DECRYPT {sni} ({key[1]}:{key[2]}) short_pkts={len(shorts)} ===")
    # choose cipher once by trying to open the first decryptable packet per dir
    streams_c2s={}; streams_s2c={}
    largest={'c2s':-1,'s2c':-1}
    chosen={}  # dirn -> (kind,key,iv,hp)
    ok=0; bad=0
    for dirn,pk in shorts:
        sec = csec if dirn=='c2s' else ssec
        if not sec: bad+=1; continue
        # zero-length CIDs are legal & common (client often uses empty SCID)
        if dirn=='c2s': dcid_len = len(srv_scid) if srv_scid is not None else None
        else:           dcid_len = len(cli_scid) if cli_scid is not None else None
        if dcid_len is None: bad+=1; continue
        pn_off=1+dcid_len
        if pn_off+4+16>len(pk): bad+=1; continue
        cand = [chosen[dirn]] if dirn in chosen else list(try_derive(sec))
        done=False
        for tup in cand:
            name,kind,k,iv,hp = tup
            mask=hp_mask(kind,hp,pk[pn_off+4:pn_off+20])
            if mask is None: continue
            fb=pk[0]^(mask[0]&0x1f); pnlen=(fb&3)+1
            pnb=bytes(pk[pn_off+i]^mask[1+i] for i in range(pnlen))
            tpn=int.from_bytes(pnb,'big'); pn=decode_pn(tpn,pnlen*8,largest[dirn])
            hdr=bytearray(pk[:pn_off+pnlen]); hdr[0]=fb
            for i in range(pnlen): hdr[pn_off+i]=pnb[i]
            ct=pk[pn_off+pnlen:]
            nonce=bytes(iv[i]^pn.to_bytes(12,'big')[i] for i in range(12))
            try:
                pt=aead_open(kind,k,nonce,ct,bytes(hdr))
            except Exception:
                continue
            chosen[dirn]=(name,kind,k,iv,hp)
            if pn>largest[dirn]: largest[dirn]=pn
            stream_frame_parse(pt, streams_c2s if dirn=='c2s' else streams_s2c)
            ok+=1; done=True; break
        if not done: bad+=1
    print(f"    packets opened OK={ok} failed={bad}  cipher={ {d:chosen[d][0] for d in chosen} }")
    asm_c2s=assemble(streams_c2s); asm_s2c=assemble(streams_s2c)
    # locate QPACK encoder streams (uni type 0x02) per direction, set up decoders
    def find_encoder(asm):
        for sid,data in asm.items():
            u,_=h3_frames(sid,data)
            if u==0x02: return data  # includes leading type byte
        return None
    def settings(asm):
        # find control stream (uni type 0x0), parse first SETTINGS frame -> {id:val}
        for sid,data in asm.items():
            u,frames=h3_frames(sid,data)
            if u==0x00:
                for ft,body in frames:
                    if ft==0x04:
                        d={}; i=0
                        while i<len(body):
                            k,i=rd_varint(body,i); v,i=rd_varint(body,i); d[k]=v
                        return d
        return {}
    st_cli=settings(asm_c2s); st_srv=settings(asm_s2c)
    cap_srv=st_srv.get(0x01,0); bs_srv=st_srv.get(0x07,0)   # governs CLIENT encoder (requests)
    cap_cli=st_cli.get(0x01,0); bs_cli=st_cli.get(0x07,0)   # governs SERVER encoder (responses)
    print(f"    QPACK caps: server_adv={cap_srv}(bs={bs_srv}) client_adv={cap_cli}(bs={bs_cli})")
    dec_req=dec_resp=None
    if QDecoder:
        enc_c=find_encoder(asm_c2s); enc_s=find_encoder(asm_s2c)
        if enc_c is not None:
            dec_req=QDecoder(cap_srv or 65536, bs_srv or 100)
            try: dec_req.feed_encoder(enc_c[1:])
            except Exception as e: print("   [qpack req enc err]",e)
        if enc_s is not None:
            dec_resp=QDecoder(cap_cli or 65536, bs_cli or 100)
            try: dec_resp.feed_encoder(enc_s[1:])
            except Exception as e: print("   [qpack resp enc err]",e)
    def dump(label,asm,dec):
        if not asm: return
        print(f"  --- {label}: {len(asm)} streams ---")
        for sid in sorted(asm):
            data=asm[sid]; u,frames=h3_frames(sid,data)
            fn=os.path.join(OUTDIR,f"{sni}_{label}_sid{sid}.bin"); open(fn,'wb').write(data)
            tag=f"uni t=0x{u:x}" if u is not None else "bidi"
            print(f"   stream {sid} [{tag}] ({len(data)}B)")
            for ft,body in frames:
                nm=H3NAME.get(ft,f'0x{ft:x}')
                if ft==0x01 and dec is not None:  # HEADERS -> QPACK decode
                    try:
                        _ctrl,hdrs=dec.feed_header(sid,body)
                        hs=" ; ".join(f"{n.decode('latin1')}: {v.decode('latin1')}" for n,v in hdrs)
                        print(f"     H3 HEADERS   {hs}")
                    except Exception as e:
                        print(f"     H3 HEADERS   [qpack err {e}] {body[:24].hex()}")
                elif ft==0x00:  # DATA
                    prev=body[:48]; asc=''.join(chr(c) if 32<=c<127 else '.' for c in prev)
                    print(f"     H3 DATA len={len(body):<5} | {prev.hex()} | {asc}")
                else:
                    print(f"     H3 {nm} len={len(body)}")
    dump('C2S',asm_c2s,dec_req)
    dump('S2C',asm_s2c,dec_resp)

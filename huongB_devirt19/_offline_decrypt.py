import json,sys,binascii,os
from Crypto.Cipher import AES
def h2b(s): return binascii.unhexlify(s) if s else b''
def score(pt):
    if not pt: return 0
    # printable ratio
    pr=sum(1 for c in pt if 9<=c<=13 or 32<=c<=126)/len(pt)
    s=pr*100
    # protobuf-ish: leading field tags small
    if pt[:1] and (pt[0]&0x7)<=5 and (pt[0]>>3)>0 and (pt[0]>>3)<20: s+=15
    if pt[:2]==b'\x1f\x8b': s+=80   # gzip
    if pt[:1]==b'{' or pt[:1]==b'[': s+=40
    if b'sdi' in pt or b'device' in pt or b'did' in pt or b'\x0a' in pt[:4]: s+=10
    return round(s,1)
def try_all(ct,key,iv,tag):
    out=[]
    for klen in ([len(key)] if len(key) in (16,24,32) else [16,24,32]):
        k=key[:klen] if len(key)>=klen else key.ljust(klen,b'\0')
        ivv=(iv+b'\0'*16)[:16] if iv else b'\0'*16
        try: out.append(('CBC',AES.new(k,AES.MODE_CBC,ivv).decrypt(ct[:len(ct)//16*16])))
        except Exception as e: pass
        try: out.append(('CTR',AES.new(k,AES.MODE_CTR,nonce=b'',initial_value=ivv).decrypt(ct)))
        except: pass
        try: out.append(('CFB',AES.new(k,AES.MODE_CFB,ivv,segment_size=128).decrypt(ct)))
        except: pass
        try: out.append(('OFB',AES.new(k,AES.MODE_OFB,ivv).decrypt(ct)))
        except: pass
        try: out.append(('ECB',AES.new(k,AES.MODE_ECB).decrypt(ct[:len(ct)//16*16])))
        except: pass
    res=[]
    for mode,pt in out:
        res.append((score(pt),tag,klen,mode,pt))
    return res
def main():
    cap=json.load(open("_spawn_capture.json"))
    dump=cap['dump']
    tuples=[]
    for e in dump:
        if e.get('t')=='EINIT' and e.get('key'):
            tuples.append((h2b(e['key']),h2b(e.get('iv') or ''),bool(e.get('armed')),e.get('keyBytes')))
    # dedupe, armed first
    seen=set(); ded=[]
    for t in sorted(tuples,key=lambda x:not x[2]):
        kk=(t[0],t[1]); 
        if kk in seen: continue
        seen.add(kk); ded.append(t)
    print("distinct key/iv tuples:",len(ded))
    stores={}
    for f in os.listdir("_msdump_live"):
        if '.ms' in f:
            stores[f]=open(os.path.join("_msdump_live",f),'rb').read()
    allres=[]
    for fn,ct in stores.items():
        for key,iv,armed,kb in ded:
            for r in try_all(ct,key,iv,fn+('*' if armed else '')):
                allres.append(r+ (armed,))
    allres.sort(key=lambda x:-x[0])
    print("=== TOP 25 candidates (score,file,klen,mode) ===")
    for sc,tag,klen,mode,pt,armed in allres[:25]:
        print("  %5.1f %-46s k%d %-4s armed=%s  %s"%(sc,tag,klen,mode,armed,pt[:40].hex()))
        if sc>=100:
            print("       PT:",repr(pt[:80]))
if __name__=="__main__": main()

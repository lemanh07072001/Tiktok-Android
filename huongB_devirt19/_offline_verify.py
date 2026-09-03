#!/usr/bin/env python3
# Given (key, iv, in, out) captured from a store crypt, find WHICH AES mode
# reproduces out from in offline -> proves the store cipher statically.
import sys, json
from Crypto.Cipher import AES
def h2b(h): return bytes.fromhex(h) if h else b""
def try_modes(key, iv, pt, ct):
    res=[]
    K=h2b(key); IV=h2b(iv); PT=h2b(pt); CT=h2b(ct)
    if not K or not PT or not CT: return [("skip","missing key/in/out")]
    n=min(len(PT),len(CT))
    def eq(a): return a[:n]==CT[:n]
    # CTR (counter from IV)
    try:
        from Crypto.Util import Counter
        ctr=Counter.new(128, initial_value=int.from_bytes(IV[:16].ljust(16,b'\0'),'big')) if IV else Counter.new(128)
        c=AES.new(K, AES.MODE_CTR, counter=ctr); o=c.encrypt(PT)
        if eq(o): res.append(("CTR-enc","MATCH"))
    except Exception as e: res.append(("CTR",str(e)[:40]))
    for name,mode,neediv in [("CBC",AES.MODE_CBC,1),("CFB",AES.MODE_CFB,1),("OFB",AES.MODE_OFB,1),("ECB",AES.MODE_ECB,0)]:
        try:
            if neediv and len(IV)<16: continue
            kw=dict(iv=IV[:16]) if neediv else {}
            if name=="CFB": kw["segment_size"]=128
            c=AES.new(K,mode,**kw)
            L=(n//16)*16 if name in("CBC","ECB") else n
            if L==0: continue
            o=c.encrypt(PT[:L])
            if o[:L]==CT[:L]: res.append((name+"-enc","MATCH"))
            # also try decrypt direction (maybe captured in=ct,out=pt)
            c2=AES.new(K,mode,**(dict(iv=IV[:16]) if neediv else {}))
            if name=="CFB": pass
            o2=c2.decrypt(CT[:L]) if hasattr(c2,'decrypt') else None
            if o2 and o2[:L]==PT[:L]: res.append((name+"-dec","MATCH"))
        except Exception as e: res.append((name,str(e)[:40]))
    return res
if __name__=="__main__":
    # read a hit dict from argv json or from _match_out.json first store-sized cap
    if len(sys.argv)>1:
        d=json.loads(sys.argv[1])
        print(try_modes(d.get("key"),d.get("iv"),d.get("in"),d.get("out")))
    else:
        print("usage: _offline_verify.py '{\"key\":..,\"iv\":..,\"in\":..,\"out\":..}'")

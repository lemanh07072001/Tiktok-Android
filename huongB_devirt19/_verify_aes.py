import re, sys
from Crypto.Cipher import AES

def wswap4(hexs):
    b=bytes.fromhex(hexs); out=bytearray(len(b))
    for i in range(0,len(b),4): out[i:i+4]=b[i:i+4][::-1]
    return bytes(out)

def wswap_all(b):
    out=bytearray(len(b))
    for i in range(0,len(b),4): out[i:i+4]=b[i:i+4][::-1]
    return bytes(out)

txt=open('_oracle_out.txt').read().splitlines()

def parse(kind):
    # kind 'ENC' -> hdr key/iv, body=PT then CT ; 'DEC' -> hdr, body=CT then PT
    hdr = re.compile(r'^\['+kind+r' (pt|ct)\] ctx=(\S+) len=(\d+) key0=([0-9a-f]+) iv=([0-9a-f]+)')
    tuples=[]
    i=0
    while i < len(txt):
        m=hdr.match(txt[i])
        if m:
            ln=int(m.group(3)); key0=m.group(4); iv=m.group(5)
            # next two data lines
            d1=txt[i+1] if i+1<len(txt) else ''
            d2=txt[i+2] if i+2<len(txt) else ''
            a=re.match(r'^\['+kind+r' (pt|ct)\] ([0-9a-f<]+)', d1)
            b=re.match(r'^\['+kind+r' (pt|ct)\] ([0-9a-f<]+)', d2)
            if a and b:
                tuples.append((ln,key0,iv,a.group(1),a.group(2),b.group(1),b.group(2)))
            i+=3; continue
        i+=1
    return tuples

def hx(b): return b.hex()

def test_enc(t):
    ln,key0,iv,l1,v1,l2,v2 = t
    # l1 should be 'pt', l2 'ct'
    pt=bytes.fromhex(v1); ct=bytes.fromhex(v2); IV=bytes.fromhex(iv)
    userKey=wswap4(key0)
    trials={
      'std(userKey)': lambda k,p: AES.new(userKey,AES.MODE_CBC,IV).encrypt(p),
      'std(key0raw)': lambda k,p: AES.new(bytes.fromhex(key0),AES.MODE_CBC,IV).encrypt(p),
    }
    res={}
    for name,fn in trials.items():
        try: res[name]= (fn(None,pt)==ct)
        except Exception as e: res[name]='ERR:'+str(e)
    # word-swapped state variant: swap pt words, enc with userKey, swap ct words
    try:
        e = AES.new(userKey,AES.MODE_CBC, wswap_all(IV)).encrypt(wswap_all(pt))
        res['wswap-state(userKey)'] = (wswap_all(e)==ct)
    except Exception as e: res['wswap-state']='ERR'
    return userKey,res

def test_dec(t):
    ln,key0,iv,l1,v1,l2,v2 = t
    ct=bytes.fromhex(v1); pt=bytes.fromhex(v2); IV=bytes.fromhex(iv)
    userKey=wswap4(key0)
    res={}
    try: res['std(userKey)']= (AES.new(userKey,AES.MODE_CBC,IV).decrypt(ct)==pt)
    except Exception as e: res['std(userKey)']='ERR:'+str(e)
    try: res['std(key0raw)']= (AES.new(bytes.fromhex(key0),AES.MODE_CBC,IV).decrypt(ct)==pt)
    except Exception as e: res['std(key0raw)']='ERR'
    return userKey,pt,res

print("=== ENC tuples ===")
enc=parse('ENC')
print("count:",len(enc))
if enc:
    uk,res=test_enc(enc[0])
    print("userKey(wswap key0)=",uk.hex())
    for k,v in res.items(): print("  ",k,"->",v)

print("\n=== DEC tuples ===")
dec=parse('DEC')
print("count:",len(dec))
for idx,t in enumerate(dec[:6]):
    uk,pt,res=test_dec(t)
    print(f"[{idx}] len={t[0]} userKey={uk.hex()} iv={t[2]}")
    for k,v in res.items(): print("    ",k,"->",v)
    # show plaintext head to eyeball protobuf
    print("     pt[0:32]=",pt[:32].hex(), " ascii=", ''.join(chr(c) if 32<=c<127 else '.' for c in pt[:32]))

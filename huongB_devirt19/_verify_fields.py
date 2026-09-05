import importlib.util, struct
spec = importlib.util.spec_from_file_location("it", "_inner_test.py")
it = importlib.util.module_from_spec(spec); spec.loader.exec_module(it)

MAGIC6 = bytes.fromhex("08d2a4808204")

def walk(rep):
    out=[]; i=0; n=len(rep)
    while i < n:
        b=rep[i]; i+=1
        fn=b>>3; wt=b&7
        if b==0: break
        if wt==0:
            v=0; sh=0
            while i<n and (rep[i]&0x80): v|=(rep[i]&0x7f)<<sh; sh+=7; i+=1
            if i<n: v|=(rep[i]&0x7f)<<sh; i+=1
            out.append((fn,"varint",-1,str(v)))
        elif wt==2:
            ln=0; sh=0
            while i<n and (rep[i]&0x80): ln|=(rep[i]&0x7f)<<sh; sh+=7; i+=1
            if i<n: ln|=(rep[i]&0x7f)<<sh; i+=1
            data=rep[i:i+ln]; i+=ln
            pv=data[:28].hex()
            try:
                a=data.decode('ascii')
                if a.isprintable(): pv='"'+a[:44]+'"'
            except: pass
            out.append((fn,"bytes",ln,pv))
        elif wt==5: out.append((fn,"i32",4,rep[i:i+4].hex())); i+=4
        elif wt==1: out.append((fn,"i64",8,rep[i:i+8].hex())); i+=8
        else: out.append((fn,"?wt%d"%wt,0,"stop")); break
    return out

pts,_ = it.parse_pts()
targets={13,14,19,20,24}
picks=[]
seenL=set()
for idx,(iev,L,pt) in enumerate(pts):
    if idx<82 and L in (544,560,576) and L not in seenL:
        picks.append((idx,iev,L,pt)); seenL.add(L)
    if len(seenL)>=3: break

for idx,iev,L,pt in picks:
    hit=None
    for rb01 in range(65536):
        rbb=bytes([rb01>>8,rb01&0xff])
        rep=it.full_decode(pt,rbb,it.SIGN_KEY,9,15,'revxor',None,0,4,False)
        if rep and rep[:6]==MAGIC6:
            hit=(rbb,rep); break
    if not hit:
        print(f"\n=== pt idx{idx} L={L}: NO HIT ==="); continue
    rbb,rep=hit
    f=walk(rep)
    nums=sorted(set(x[0] for x in f))
    print(f"\n=== pt idx{idx} (ev i={iev}) L={L} -> report {len(rep)}B rb01={rbb.hex()} ===")
    print("top-level field numbers:", nums)
    print("target {13,14,19,20,24}:", {t:(t in nums) for t in sorted(targets)})
    for fn,wt,ln,pv in f:
        tag=" <== TARGET" if fn in targets else ""
        print(f"  #{fn:<3} {wt:<7} len={ln:<5} {pv[:64]}{tag}")

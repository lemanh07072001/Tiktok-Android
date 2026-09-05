import os

def rdvar(rep,i):
    v=0; sh=0
    while i<len(rep):
        b=rep[i]; i+=1
        v |= (b&0x7f)<<sh
        if not (b&0x80): break
        sh+=7
    return v,i

def walk(rep, label):
    print(f"\n=== {label}: {len(rep)}B, head={rep[:6].hex()} ===")
    out=[]; i=0; n=len(rep); zeros=0
    while i < n:
        if rep[i]==0:
            j=i
            while j<n and rep[j]==0: j+=1
            if j-i>=4: print(f"  [padding: {j-i}x0x00 @off{i} -> stop]"); break
            i=j; continue
        tag,i = rdvar(rep,i)
        fn=tag>>3; wt=tag&7
        if fn==0 or wt in (3,4,6,7):
            print(f"  [stop: bad tag fn={fn} wt={wt} @off]"); break
        if wt==0:
            v,i=rdvar(rep,i); out.append(fn); print(f"  #{fn:<3} varint  = {v}")
        elif wt==2:
            ln,i=rdvar(rep,i); data=rep[i:i+ln]; i+=ln
            pv=data[:40].hex()
            try:
                a=data.decode('ascii')
                if a.isprintable(): pv='"'+a[:56]+'"'
            except: pass
            out.append(fn); print(f"  #{fn:<3} bytes[{ln:<4}] {pv}")
        elif wt==5: out.append(fn); print(f"  #{fn:<3} i32 = {rep[i:i+4].hex()}"); i+=4
        elif wt==1: out.append(fn); print(f"  #{fn:<3} i64 = {rep[i:i+8].hex()}"); i+=8
    print("  FIELD SET:", sorted(set(out)))
    print("  targets:", {t:(t in out) for t in (13,14,16,17,18,19,20,24)})
    return out

p="offline_inner_report.hex"
h=open(p).read().strip().replace(" ","").replace("\n","")
walk(bytes.fromhex(h), "offline_inner_report.hex (GENUINE decoded report)")

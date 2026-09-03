import re
txt=open('_oracle_out.txt').read().splitlines()
i=0
while i<len(txt):
    m=re.match(r'^\[DEC ct\] ctx=(\S+) len=(\d+) key0=([0-9a-f]+) iv=([0-9a-f]+)',txt[i])
    if m:
        ct=re.match(r'^\[DEC ct\] ([0-9a-f]+)',txt[i+1])
        pt=re.match(r'^\[DEC pt\] ([0-9a-f]+)',txt[i+2])
        def ws(h):
            b=bytes.fromhex(h);o=bytearray(len(b))
            for j in range(0,len(b),4):o[j:j+4]=b[j:j+4][::-1]
            return o.hex()
        print("LEN",m.group(2),"userKey",ws(m.group(3)),"iv",m.group(4))
        if ct: print("  CT",ct.group(1))
        i+=3;continue
    i+=1

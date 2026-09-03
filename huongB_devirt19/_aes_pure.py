# Minimal pure-python AES (128/192/256) ECB block ops. For analysis only.
_sbox=[]
def _init():
    global _sbox,_inv
    p=1;q=1;sbox=[0]*256
    # generate sbox
    def xtime(a): return ((a<<1)^0x1B)&0xFF if a&0x80 else (a<<1)&0xFF
    # use standard table via multiplicative inverse in GF(2^8)
    inv=[0]*256
    # build log/antilog with generator 3
    log=[0]*256; alog=[0]*256; a=1
    for i in range(255):
        alog[i]=a
        a^= xtime(a) if False else 0
    # simpler: precompute inverse by brute using gf mul
    def gmul(x,y):
        r=0
        for _ in range(8):
            if y&1: r^=x
            hi=x&0x80
            x=(x<<1)&0xFF
            if hi: x^=0x1B
            y>>=1
        return r
    invtab=[0]*256
    for x in range(256):
        for y in range(256):
            if gmul(x,y)==1:
                invtab[x]=y;break
    sbox=[0]*256
    for x in range(256):
        b=invtab[x]
        s=b^((b<<1|b>>7)&0xFF)^((b<<2|b>>6)&0xFF)^((b<<3|b>>5)&0xFF)^((b<<4|b>>4)&0xFF)^0x63
        sbox[x]=s&0xFF
    _sbox=sbox
_init()
Rcon=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D]
def _expand(key):
    Nk=len(key)//4; Nr={4:10,6:12,8:14}[Nk]
    w=[list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk,4*(Nr+1)):
        t=list(w[i-1])
        if i%Nk==0:
            t=t[1:]+t[:1]
            t=[_sbox[x] for x in t]
            t[0]^=Rcon[i//Nk-1]
        elif Nk>6 and i%Nk==4:
            t=[_sbox[x] for x in t]
        w.append([w[i-Nk][j]^t[j] for j in range(4)])
    return w,Nr
def _gmul(x,y):
    r=0
    for _ in range(8):
        if y&1: r^=x
        hi=x&0x80; x=(x<<1)&0xFF
        if hi: x^=0x1B
        y>>=1
    return r
def encrypt_block(key,blk):
    w,Nr=_expand(key)
    s=[[blk[r+4*c] for c in range(4)] for r in range(4)]
    def addrk(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c]^=w[rnd*4+c][r]
    addrk(0)
    for rnd in range(1,Nr):
        s=[[_sbox[s[r][c]] for c in range(4)] for r in range(4)]
        s=[s[r][r:]+s[r][:r] for r in range(4)]
        ns=[[0]*4 for _ in range(4)]
        for c in range(4):
            col=[s[r][c] for r in range(4)]
            ns[0][c]=_gmul(col[0],2)^_gmul(col[1],3)^col[2]^col[3]
            ns[1][c]=col[0]^_gmul(col[1],2)^_gmul(col[2],3)^col[3]
            ns[2][c]=col[0]^col[1]^_gmul(col[2],2)^_gmul(col[3],3)
            ns[3][c]=_gmul(col[0],3)^col[1]^col[2]^_gmul(col[3],2)
        s=ns; addrk(rnd)
    s=[[_sbox[s[r][c]] for c in range(4)] for r in range(4)]
    s=[s[r][r:]+s[r][:r] for r in range(4)]
    addrk(Nr)
    return bytes(s[r][c] for c in range(4) for r in range(4))
def _inc(ctr):
    c=bytearray(ctr)
    for i in range(15,-1,-1):
        c[i]=(c[i]+1)&0xFF
        if c[i]: break
    return bytes(c)
def ctr_keystream(key,iv,n):
    out=b"";c=iv
    while len(out)<n:
        out+=encrypt_block(key,c); c=_inc(c)
    return out[:n]
def ofb_keystream(key,iv,n):
    out=b"";x=iv
    while len(out)<n:
        x=encrypt_block(key,x); out+=x
    return out[:n]
if __name__=="__main__":
    # NIST AES-128 ECB test vector
    k=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    p=bytes.fromhex("00112233445566778899aabbccddeeff")
    print("selftest", encrypt_block(k,p).hex(), "expect 69c4e0d86a7b0430d8cdb78070b4c55a")

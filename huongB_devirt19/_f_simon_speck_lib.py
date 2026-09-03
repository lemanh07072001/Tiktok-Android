#!/usr/bin/env python3
# Comprehensive Simon/Speck black-box closure using the VALIDATED simonspeckciphers lib.
# slot16 = 16B = 128-bit block. Test single-128-block Simon & Speck (key 128/192/256), plus
# 2x64-bit-block interpretations, with (A) decrypt-and-look and (B) seed-as-key const-block.
import json
from simon import SimonCipher
from speck import SpeckCipher

G=json.load(open('_corr_data.json'))
PSK=bytes.fromhex(G[0]['mat'])
seeds=[bytes.fromhex(r['seed']) for r in G]
slots=[bytes.fromhex(r['slot16']) for r in G]

def load_embedded():
    keys={'emb_19b520':bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b")}
    try:
        from elftools.elf.elffile import ELFFile
        f=open('bin/libmetasec_ov.so','rb'); elf=ELFFile(f)
        segs=[(s['p_vaddr'],s['p_offset'],s['p_filesz']) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
        def rd(va,n):
            for v,o,sz in segs:
                if v<=va<v+sz: f.seek(o+(va-v)); return f.read(n)
            return None
        for va,cnt,tag in [(0x960,5,'data960'),(0x17baa0,2,'rod17baa0')]:
            b=rd(va,16*cnt)
            if b:
                for i in range(cnt): keys['%s_%d'%(tag,i)]=b[i*16:(i+1)*16]
    except Exception as e: print("[!] emb:",e)
    return keys

KEYS={'PSK32':PSK,'PSK16lo':PSK[:16],'PSK16hi':PSK[16:],'PSK24':PSK[:24]}
KEYS.update(load_embedded())

def dec128(key, ct):
    """decrypt 16B ct as single 128-bit block; yield (name, pt16) for Simon & Speck valid keysizes."""
    kl=len(key); out=[]
    if kl not in (16,24,32): return out
    ks=kl*8; ki=int.from_bytes(key,'big'); ci=int.from_bytes(ct,'big')
    for algo,Cls in (('Simon',SimonCipher),('Speck',SpeckCipher)):
        try:
            c=Cls(ki,key_size=ks,block_size=128)
            pt=c.decrypt(ci).to_bytes(16,'big'); out.append(('%s128/%d'%(algo,ks),pt))
        except Exception: pass
    # also try key interpreted little-endian
    kil=int.from_bytes(key,'little')
    for algo,Cls in (('Simon',SimonCipher),('Speck',SpeckCipher)):
        try:
            c=Cls(kil,key_size=ks,block_size=128)
            pt=c.decrypt(ci).to_bytes(16,'big'); out.append(('%s128/%d_kLE'%(algo,ks),pt))
        except Exception: pass
    return out

print("=== (A) decrypt-and-look (Simon/Speck 128) ===")
hits=0; lowvar=[]
for kn,kb in KEYS.items():
    names=[n for n,_ in dec128(kb, slots[0])]
    for name in names:
        pts=[]
        for ct in slots:
            d=dict(dec128(kb,ct)); pts.append(d.get(name))
        if any(p is None or len(p)!=16 for p in pts): continue
        varmask=[1 if len({p[j] for p in pts})>1 else 0 for j in range(16)]
        nvar=sum(varmask)
        # contiguous run of exactly 4 == seed?
        j=0
        while j<16:
            if varmask[j]:
                k=j
                while k<16 and varmask[k]: k+=1
                if k-j==4:
                    for orient in('fwd','rev'):
                        if all(pts[i][j:j+4]==(seeds[i] if orient=='fwd' else seeds[i][::-1]) for i in range(13)):
                            print("  *** SEED-EXACT:",kn,name,"@",j,orient); hits+=1
                j=k
            else: j+=1
        if nvar<=6: lowvar.append((nvar,kn,name,''.join(map(str,varmask))))
if not hits:
    print("  no seed-exact hit.")
    lowvar.sort()
    for v in lowvar[:12]: print("   lowvar nvar=%d %s %s mask=%s"%v)

print("\n=== (B) seed-as-key const-block (Simon/Speck 128) ===")
def seed_keys(seed):
    return {'seedx4':seed*4,'seedx8':seed*8,'seed_z16':seed+b'\0'*12,'seed_z32':seed+b'\0'*28,
            'seed_psk16':(seed+PSK)[:16],'seed_psk32':(seed+PSK)[:32],'psk_seed16':(PSK[:12]+seed)}
bhit=0
for variant in ['seedx4','seedx8','seed_z16','seed_z32','seed_psk16','seed_psk32','psk_seed16']:
    results={}
    for i in range(13):
        kb=seed_keys(seeds[i])[variant]
        for name,pt in dec128(kb, slots[i]): results.setdefault(name,[]).append(pt)
    for name,lst in results.items():
        if len(lst)==13 and len(set(lst))==1:
            print("  *** CONST-BLOCK:",variant,name,"->",lst[0].hex()); bhit+=1
if not bhit: print("  no const-block hit.")
print("\n[done] seed-exact=%d const-block=%d"%(hits,bhit))

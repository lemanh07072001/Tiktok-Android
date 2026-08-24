#!/usr/bin/env python3
# TEST: slot16 (=> #19 nonzero preimage) co phai ham tat dinh cua input OFFLINE khong?
# Yeu cau khop CA 3 clean tuple (cung keva state, khac _rticket) moi tinh HIT.
# Inputs offline that: k18(#18), PSK material 32B (da reproduce offline bit-exact), keva ecneuq/semithc, _rticket/ts.
import hashlib, hmac, struct, itertools, json
from sm3_hash19 import sm3   # stock SM3 (KAT-verified)

H = bytes.fromhex
def md5(b):  return hashlib.md5(b).digest()
def sha1(b): return hashlib.sha1(b).digest()
def sha256(b): return hashlib.sha256(b).digest()
HASHES = {'md5':md5,'sha1':sha1,'sha256':sha256,'sm3':sm3}

# ---- real offline inputs (device 7666223875861513749) ----
k18   = H('902a576684ffa6c918ace9537488afb5')          # #18 device pskHash (16B)
mat   = H('c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163')  # PSK material 32B
mat_lo, mat_hi = mat[:16], mat[16:]
ecneuq  = H('94199bca6d60ed2e')                          # 8B
semithc = H('06c89feae2d013cceab9ad17')                  # 12B
wayval  = H('d8b4d76cf5fabed1a711b5de') + H('08a39e6765657586')
waycnt  = H('1035d1b5c49a1700') + H('2c8a4df765d2dd85') + H('4c617a6c1c7550953ef5bd09')

TUPLES = [  # cung keva state, khac _rticket -> khac slot16
  ('1787492671771','1787492671','dbc927b5d95a976dd536fd319a609e77'),
  ('1787492672070','1787492672','528c1749aaaa6bb985cf445ee1a1ad3f'),
  ('1787492716235','1787492716','0368525bbc8948577a33284cac9c660d'),
]
targets = [H(t[2]) for t in TUPLES]

# encodings cua 1 gia tri timestamp (str) -> nhieu dang bytes
def enc_ts(s):
    out = {'ascii': s.encode()}
    n = int(s)
    for w,tag in ((4,'u32'),(8,'u64')):
        try:
            out[f'{tag}le'] = n.to_bytes(w,'little')
            out[f'{tag}be'] = n.to_bytes(w,'big')
        except OverflowError:
            pass
    return out

# key material candidates
KEYS = {'k18':k18,'mat':mat,'mat_lo':mat_lo,'mat_hi':mat_hi,'ecneuq':ecneuq,
        'semithc':semithc,'wayval':wayval,'waycnt':waycnt}
# static prefixes/suffixes (device-stable, same for all 3 tuples)
STATIC = dict(KEYS)
STATIC['mat+k18']   = mat+k18
STATIC['k18+mat']   = k18+mat
STATIC['ecn+sem']   = ecneuq+semithc
STATIC['mat+ecn+sem']= mat+ecneuq+semithc

def slices(d):  # 16-byte candidate views of a digest
    return {'[:16]':d[:16], '[-16:]':d[-16:], 'swap[:16]':d[:16][::-1]}

def check_all(fn):
    """fn(rticket_str, ts_str) -> 16B or None. Return list of matched tuple idx."""
    hits=[]
    for i,(rt,ts,_) in enumerate(TUPLES):
        try:
            v = fn(rt,ts)
        except Exception:
            return []
        if v is not None and v == targets[i]:
            hits.append(i)
    return hits

results=[]
def emit(desc, fn):
    hits = check_all(fn)
    if len(hits)>=1:
        results.append((len(hits),desc,hits))

# ---- construction family 1: HASH(static [|| per_req_ts_enc]) sliced ----
for hname,hf in HASHES.items():
    for sname,sval in STATIC.items():
        # static-only (would give SAME slot16 for all 3 -> can only match if all 3 equal, they arent; still test)
        for slname,_ in slices(hf(sval)).items():
            emit(f'{hname}({sname}){slname}[static]', lambda rt,ts,hf=hf,sv=sval,sl=slname: slices(hf(sv))[sl])
        # static || rticket / ts   (all encodings, both orders)
        for which in ('rt','ts'):
            def mk(hf,sv,which,enc,order,sl):
                def f(rt,ts):
                    e = enc_ts(rt if which=='rt' else ts)[enc]
                    msg = sv+e if order=='SE' else e+sv
                    return slices(hf(msg))[sl]
                return f
            for enc in enc_ts('1787492671771'):
                for order in ('SE','ES'):
                    for sl in ('[:16]','[-16:]','swap[:16]'):
                        emit(f'{hname}({sname}{"||" if order=="SE" else "<<"}{which}.{enc}){sl}',
                             mk(hf,sval,which,enc,order,sl))

# ---- construction family 2: HMAC(key, ts_enc) and HMAC(key, static||ts) ----
for hname,hf in [('md5',hashlib.md5),('sha1',hashlib.sha1),('sha256',hashlib.sha256)]:
    for kname,kval in KEYS.items():
        for which in ('rt','ts'):
            def mk(hf,kv,which,enc,sl):
                def f(rt,ts):
                    e = enc_ts(rt if which=='rt' else ts)[enc]
                    d = hmac.new(kv,e,hf).digest()
                    return slices(d)[sl]
                return f
            for enc in enc_ts('1787492671771'):
                for sl in ('[:16]','[-16:]'):
                    emit(f'HMAC-{hname}({kname},{which}.{enc}){sl}', mk(hf,kval,which,enc,sl))

# ---- construction family 3: AES-ECB(key, block) single 16B block ----
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def aes_ecb(key,pt):
        c=Cipher(algorithms.AES(key),modes.ECB()); e=c.encryptor(); return e.update(pt)+e.finalize()
    def aes_dec(key,ct):
        c=Cipher(algorithms.AES(key),modes.ECB()); d=c.decryptor(); return d.update(ct)+d.finalize()
    AES_KEYS={'mat':mat,'mat_lo':mat_lo,'mat_hi':mat_hi,'k18':k18,'k18||k18':k18+k18}
    for kname,kv in AES_KEYS.items():
        if len(kv) not in (16,32): continue
        for which in ('rt','ts'):
            for enc in ('u64le','u64be','u32le','u32be'):
                def mk(kv,which,enc,mode):
                    def f(rt,ts):
                        e=enc_ts(rt if which=='rt' else ts).get(enc)
                        if e is None: return None
                        pt=(e+b'\x00'*16)[:16]
                        return aes_ecb(kv,pt) if mode=='enc' else aes_dec(kv,pt)
                    return f
                emit(f'AES-enc({kname},{which}.{enc}pad)', mk(kv,which,enc,'enc'))
                emit(f'AES-dec({kname},{which}.{enc}pad)', mk(kv,which,enc,'dec'))
    # AES(key=mat_lo, pt=mat_hi) etc (static, no ts) -- test if slot16 is fixed transform of material
    for kn,kv in (('mat_lo',mat_lo),('mat_hi',mat_hi),('k18',k18)):
        for pn,pv in (('mat_hi',mat_hi),('mat_lo',mat_lo),('k18',k18)):
            emit(f'AES-enc({kn},{pn})[static]', lambda rt,ts,kv=kv,pv=pv: aes_ecb(kv,pv))
except ImportError:
    print('[!] cryptography not available, skip AES family')

# ---- report ----
print(f'\n=== brute over {sum(1 for _ in [0])} ... total constructions tested (multi-family) ===')
print(f'Targets (3 clean tuples, same keva state, differ only _rticket):')
for rt,ts,s16 in TUPLES: print(f'   _rticket={rt} slot16={s16}')
print()
if not results:
    print('RESULT: 0 constructions matched ANY tuple.')
else:
    results.sort(reverse=True)
    print(f'RESULT: {len(results)} constructions matched >=1 tuple:')
    for n,desc,hits in results[:40]:
        print(f'   [{n}/3] {desc}  hits={hits}')
full = [r for r in results if r[0]==3]
print()
print(f'>>> constructions matching ALL 3 tuples: {len(full)}')
for n,desc,hits in full: print(f'    HIT: {desc}')

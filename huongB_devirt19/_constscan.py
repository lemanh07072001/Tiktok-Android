#!/usr/bin/env python3
# Quét toàn .so tìm chữ ký hằng số crypto đã biết + dump đầu các const-blob VM.
import struct, binascii
SO='bin/libmetasec_ov.so'; data=open(SO,'rb').read()

SIGS={
 'AES_sbox'      : bytes.fromhex('637c777bf26b6fc53001672bfed7ab76'),
 'AES_inv_sbox'  : bytes.fromhex('52096ad53036a538bf40a39e81f3d7fb'),
 'AES_Te0_first' : bytes.fromhex('c66363a5'),   # weak
 'SHA256_K0'     : bytes.fromhex('428a2f98'),    # big-endian
 'SHA256_K0_le'  : bytes.fromhex('982f8a42'),
 'SHA1_H'        : bytes.fromhex('67452301efcdab89'),
 'MD5_T1'        : bytes.fromhex('78a46ad7'),     # d76aa478 LE-> stored 78a46ad7? check both
 'MD5_T1_be'     : bytes.fromhex('d76aa478'),
 'SM3_IV'        : bytes.fromhex('7380166f4914b2b9'),  # SM3 IV big-endian
 'SM3_IV_le'     : bytes.fromhex('6f168073b9b21449'),
 'SM3_T_0x79cc'  : bytes.fromhex('79cc4519'),
 'SHA512_K0'     : bytes.fromhex('428a2f98d728ae22'),
 'Blake2_IV'     : bytes.fromhex('6a09e667f3bcc908'),
 'ChaCha_sigma'  : b'expand 32-byte k',
 'Poly1305'      : bytes.fromhex('0ffffffc'),
}
print("=== signature search over whole .so ===")
for nm,sig in SIGS.items():
    idx=[]; start=0
    while True:
        j=data.find(sig,start)
        if j<0: break
        idx.append(j); start=j+1
        if len(idx)>8: break
    if idx:
        print(f"  {nm:14} FOUND at file-off {[hex(x) for x in idx]}")
print("\n(no line above for a sig = not present)")

# dump first 96 bytes of each const-blob (VMA==file-off for these seg addresses)
def va2off(va):
    # single exec seg mapping va==off historically; find via PT_LOAD
    e_phoff=struct.unpack_from('<Q',data,0x20)[0]; e_es=struct.unpack_from('<H',data,0x36)[0]; e_pn=struct.unpack_from('<H',data,0x38)[0]
    for i in range(e_pn):
        o=e_phoff+i*e_es
        if struct.unpack_from('<I',data,o)[0]==1:
            p_off,p_va,_,p_fsz,_=struct.unpack_from('<QQQQQ',data,o+8)
            if p_va<=va<p_va+p_fsz: return p_off+(va-p_va)
    return None
print("\n=== const-blob heads ===")
for va in (0x17bbf0,0x186600,0x18a510,0x18b020,0x18cd10):
    off=va2off(va)
    b=data[off:off+96]
    print(f"  {va:#x}: {binascii.hexlify(b).decode()}")

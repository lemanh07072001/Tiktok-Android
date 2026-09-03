#!/usr/bin/env python3
# Track C decisive test: is the store = AES-GCM [ct || 16B tag]?
# Brute captured keys x nonces x AADs against the 3 ground-truth store files.
import importlib.util, types
src=open("_gcm_verify.py").read().replace("if __name__=='__main__': selftest()","")
g=types.ModuleType("g"); exec(src,g.__dict__)
V=g.gcm_verify_decrypt

H=bytes.fromhex
FILES={
 "msf3": (H("08134acf42c8f4127fd3a3e98b4b7956"), None),   # keyname unknown
 "msp":  (H("c3b27a642260175cb483156827c01af211c80898a388e216041d8306636107a5eb8f2c85ba76df056d8f50c9b3606272af4be83ddf57812ff0df85482aa488d90bcb1448e4dcb291bb1d409a1b0c1744a24e07b7de7f635f7cda9210c25537e4de80e3f5301037a452b73786b3ae91e57f78790565b8c39e2f74d7b67ec253256983df"), "sdi_v2"),
 "mss":  (H("75aa62270249304c2290151a22d4ca79ed68d9bb3d8a01b839b7004dcb41051a6e473e8bf57c5393601f8127f0f59a0821fa1df9b9eea813b29649c6484e2f90ac81f4643befb3e3358dfd3808ebc9ee461818ed6f5510e65d5ba7c1240412a329f16f8afb1737c2cb5583f288a7a29ed182eec879f26d31e54a7c6d6a31792fc7379f983039123ca77f710d34a9b80676f7ac9196116a3588e0806978dc095a2f803bb4e71af92a0d19c09ac3579beec6ff2bed18bbd51138210d487f1c8344a2fe4c94b500bbeaf429f28e09f865c954444cf86721e152caadedbd17ac8a0401da91508958b56889502e13ecdf2c6d0d8f4d9d7b784edacc1278eac810ea6b97e0209524ed"), "mssdk_setting"),
}
KEYS=[H("b8d72ddec05142948bbf2dc81d63759c"),  # byteswapped store-key candidate (PRIME)
      H("de2dd7b8944251c0c82dbf8b9c75631d"),  # schedule-form (raw)
      H("8252970d959b06db102e17d85c0ec1af"),  # req#1 key
      H("b114249b7bed9d2691d70c60d69f9c4f")]  # req#2 key
IV16=H("4d207ea37a419f7d622f81c6a2f53594")
NONCES=[IV16, IV16[:12], b'\x00'*12, b'\x00'*16]

def aads(name,keyname):
    out=[(b'', "empty")]
    if keyname:
        out.append((keyname.encode(), "keyname:"+keyname))
        # SHA1(keyname) is the FILENAME; sometimes also used as AAD
    return out

def tag_split(blob):
    return blob[:-16], blob[-16:]

hits=0; tested=0
for fname,(blob,keyname) in FILES.items():
    ct,tag=tag_split(blob)
    for ki,key in enumerate(KEYS):
        for ni,nonce in enumerate(NONCES):
            for aad,alabel in aads(fname,keyname):
                tested+=1
                try:
                    pt=V(key,nonce,ct,tag,aad)
                except Exception:
                    pt=None
                if pt is not None:
                    hits+=1
                    print(f"[HIT] file={fname} key#{ki}={key.hex()} nonce({len(nonce)}B)={nonce.hex()} aad={alabel}")
                    print(f"      plaintext({len(pt)}B)={pt.hex()}")
print(f"\n--- brute done: {tested} combos tested, {hits} tag hit(s) ---")
if hits==0:
    print("VERDICT: NO GCM tag matched with captured candidates.")
    print("  => store is NOT AES-GCM under these keys/nonces, OR the real key")
    print("     was never captured (STORE-key comes from OLLVM-VM getter 0x1182d0).")
    print("  => escalate to Path A: RDR-armed oracle read of the LIVE store key when emulator UP.")

#!/usr/bin/env python3
# Alt framings: nonce-prepended [12B nonce||ct||tag] and tag-prepended [16B tag||ct].
import types
src=open("_gcm_verify.py").read().replace("if __name__=='__main__': selftest()","")
g=types.ModuleType("g"); exec(src,g.__dict__); V=g.gcm_verify_decrypt
H=bytes.fromhex
FILES={
 "msp":  (H("c3b27a642260175cb483156827c01af211c80898a388e216041d8306636107a5eb8f2c85ba76df056d8f50c9b3606272af4be83ddf57812ff0df85482aa488d90bcb1448e4dcb291bb1d409a1b0c1744a24e07b7de7f635f7cda9210c25537e4de80e3f5301037a452b73786b3ae91e57f78790565b8c39e2f74d7b67ec253256983df"), "sdi_v2"),
 "mss":  (H("75aa62270249304c2290151a22d4ca79ed68d9bb3d8a01b839b7004dcb41051a6e473e8bf57c5393601f8127f0f59a0821fa1df9b9eea813b29649c6484e2f90ac81f4643befb3e3358dfd3808ebc9ee461818ed6f5510e65d5ba7c1240412a329f16f8afb1737c2cb5583f288a7a29ed182eec879f26d31e54a7c6d6a31792fc7379f983039123ca77f710d34a9b80676f7ac9196116a3588e0806978dc095a2f803bb4e71af92a0d19c09ac3579beec6ff2bed18bbd51138210d487f1c8344a2fe4c94b500bbeaf429f28e09f865c954444cf86721e152caadedbd17ac8a0401da91508958b56889502e13ecdf2c6d0d8f4d9d7b784edacc1278eac810ea6b97e0209524ed"), "mssdk_setting"),
}
KEYS=[H("b8d72ddec05142948bbf2dc81d63759c"),H("de2dd7b8944251c0c82dbf8b9c75631d"),
      H("8252970d959b06db102e17d85c0ec1af"),H("b114249b7bed9d2691d70c60d69f9c4f")]
hits=0;tested=0
for fname,(blob,keyname) in FILES.items():
  aadset=[(b'',"empty"),(keyname.encode(),"keyname")]
  frames=[]
  # A) nonce-prepended: [12B nonce || ct || 16B tag]
  frames.append(("nonce12-prepend", blob[:12], blob[12:-16], blob[-16:]))
  # B) nonce16-prepend: [16B nonce || ct || 16B tag]
  frames.append(("nonce16-prepend", blob[:16], blob[16:-16], blob[-16:]))
  # C) tag-prepended: [16B tag || ct], nonce from candidates (handled below w/ external nonce)
  for label,nonce,ct,tag in frames:
    for ki,key in enumerate(KEYS):
      for aad,al in aadset:
        tested+=1
        try: pt=V(key,nonce,ct,tag,aad)
        except Exception: pt=None
        if pt is not None:
          hits+=1
          print(f"[HIT] {fname} frame={label} key#{ki} aad={al} nonce={nonce.hex()}")
          print(f"      pt({len(pt)}B)={pt.hex()}")
print(f"\n--- alt-framing brute: {tested} combos, {hits} hit(s) ---")

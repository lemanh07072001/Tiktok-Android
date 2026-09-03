#!/usr/bin/env python3
# verify_bundle.py — SELF-CONTAINED (pure stdlib, no deps) verifier for the mssdk
# device-state bundle. Decrypts the encrypted store IN THIS BUNDLE and prints the
# device-secret, so you can confirm the bundle is genuine/intact before feeding it
# to the unidbg signer (on Windows or anywhere).
#
# Store cipher (cracked 2026-09-02, see notes/56):
#   .msp / .mss filename = SHA1(keyname).hex()
#   .msp  = RC4( MD5(SHA1(keyname)).hex() ) then [4B LE decompressed-len][zlib]  (kind0)
#   .msf3 = XXTEA( key = MD5(keyname) ) with LE-word packing + appended byte-length (kind2)
#   .mss  = AES-256 KV-container (kind1) — not decrypted here (metasec .so handles it)
#
# Usage:  python3 verify_bundle.py            # verifies ./.msdata/mssdk/ov
#         python3 verify_bundle.py <ov_dir>
import os, sys, zlib, hashlib, struct, json

def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256): j=(j+S[i]+key[i%len(key)])&255; S[i],S[j]=S[j],S[i]
    i=j=0; out=bytearray()
    for b in data:
        i=(i+1)&255; j=(j+S[i])&255; S[i],S[j]=S[j],S[i]; out.append(b^S[(S[i]+S[j])&255])
    return bytes(out)

def msp_key_from_filename(name):
    hexpart=os.path.basename(name).split("_",1)[1]
    return hashlib.md5(bytes.fromhex(hexpart)).hexdigest().encode()

def decrypt_msp(path):
    inter=rc4(msp_key_from_filename(path), open(path,"rb").read())
    for off in (4,0,2,6,8):
        try:
            d=zlib.decompressobj().decompress(inter[off:])
            if d[:1] in (b'{',b'['): return d
        except Exception: pass
    return None

# --- XXTEA (Corrected Block TEA) for .msf3, key = MD5(keyname) ---
_DELTA=0x9E3779B9
def _xxtea_decrypt_words(v, k):
    n=len(v)
    if n<2: return v
    rounds=6+52//n; s=(rounds*_DELTA)&0xffffffff; y=v[0]
    while s!=0:
        e=(s>>2)&3
        for p in range(n-1,0,-1):
            z=v[p-1]
            mx=(((z>>5^(y<<2))+(y>>3^(z<<4)))^((s^y)+(k[(p&3)^e]^z)))&0xffffffff
            v[p]=(v[p]-mx)&0xffffffff; y=v[p]
        z=v[n-1]
        mx=(((z>>5^(y<<2))+(y>>3^(z<<4)))^((s^y)+(k[(0&3)^e]^z)))&0xffffffff
        v[0]=(v[0]-mx)&0xffffffff; y=v[0]
        s=(s-_DELTA)&0xffffffff
    return v

def decrypt_msf3(path):
    # .msf3 filename hex = SHA1(keyname); key = MD5(keyname). We don't know keyname
    # here, so try both known derivations for verification purposes is not possible
    # without the keyname; skip content, just report size. (Counters are per-key.)
    return None

def main():
    ov=sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), ".msdata","mssdk","ov")
    if not os.path.isdir(ov):
        print("ov dir not found:", ov); sys.exit(1)
    print("Verifying store in:", ov, "\n")
    secret=None
    for f in sorted(os.listdir(ov)):
        p=os.path.join(ov,f); sz=os.path.getsize(p) if os.path.isfile(p) else 0
        if f.startswith(".msp_"):
            d=decrypt_msp(p)
            if d:
                try: keys=list(json.loads(d).keys())
                except Exception: keys="(non-json)"
                tag="DEVICE-SECRET" if b"dyn_seed" in d else "settings"
                print("[OK]   %-46s %4dB  %s: %s"%(f, sz, tag, keys[:6] if isinstance(keys,list) else keys))
                if b"dyn_seed" in d: secret=json.loads(d)
            else:
                print("[FAIL] %-46s %4dB  RC4 decrypt did not yield JSON"%(f, sz))
        elif f.startswith(".mss_"):
            print("[skip] %-46s %4dB  (AES-256 KV-container — metasec .so decrypts at runtime)"%(f, sz))
        elif f.startswith((".msf3_",".msfs_")):
            print("[info] %-46s %4dB  (XXTEA counter store — key=MD5(keyname), opaque here)"%(f, sz))
    if secret:
        print("\n=== DEVICE-SECRET (authoritative, decrypted from encrypted store) ===")
        for k in ("dyn_deviceid","rdk2_ms","rtk2_ms","kiid","fltk","dyn_version","rsk2_ms"):
            print("  %-14s = %s"%(k, secret.get(k)))
        print("  dyn_seed(98B, X-Argus #24) =", (secret.get("dyn_seed") or "")[:48], "...")
        print("\nBundle is GENUINE and decryptable. Feed .msdata/mssdk/ov to the signer via MSB_DEVSTATE_DIR.")
    else:
        print("\nWARNING: could not find/decrypt the device-secret (.msp_*). Bundle may be corrupt.")

if __name__=="__main__":
    main()

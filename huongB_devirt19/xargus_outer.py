#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xargus_outer.py — CRACKED OUTER layer of X-Argus for TikTok musically 45.5.4
                  (libmetasec_ov.so md5 02f47578b5d0019120570e7be6c9da42).

OUTER envelope (verified offline in unidbg harness + against 13 genuine device captures):
    X-Argus = base64( rb01[2 bytes] || AES-128-CBC-enc(plaintext, aes_key, aes_iv) )
      aes_key = md5(SIGN_KEY[:16])
      aes_iv  = md5(SIGN_KEY[16:])
      SIGN_KEY = c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163  (BUILD CONSTANT)
    - plaintext is NOT pkcs7-padded — it is block-aligned by construction (that is why the
      2020 community decode_xargus, which does pkcs7_unpad, rejects modern samples).
    - plaintext = 9-byte header (byte0=0xec, byte5=0x01, byte8=0x18 constant) + inner body.
      The inner body is a further (Simon/reverse-XOR) layer — NOT decoded here (this file is
      only the OUTER AES-CBC layer, which is the part that was missing on Android).

Provenance of the crack (all runnable from mobile/unidbg harness, no phone):
  - Located the OUTER cipher by recording metasec 8-byte stores during an offline sign and
    matching them to the ciphertext: PC +0x159f2c writes 34/34 ct chunks.
  - Function chain: key-setup 0x159d70 (calls key-schedule 0x1591bc, w2=16 => AES-128),
    CBC-encrypt loop 0x159de4(x0=ctx[roundkeys@0, iv@+0x1e8], x1=plaintext, x2=out, x3=len).
  - Hooked 0x159de4: rk0 = word-byteswap(aes_key); aes_key=8252970d..., aes_iv=4d207ea3...
  - Verified: AES_CBC_enc(captured_PT, aes_key, aes_iv) == ct  AND  dec(ct)==PT.
  - Cross-device: the SAME key decrypts all 13 genuine captures to the constant header
    (byte0=0xec, byte5=0x01, byte8=0x18) => SIGN_KEY is a build constant, not per-device.

Usage:
    python xargus_outer.py <x-argus-b64>        # decrypt one X-Argus -> plaintext hex
    python xargus_outer.py                       # self-test on the embedded genuine sample
"""
import sys, base64, hashlib
from Crypto.Cipher import AES

SIGN_KEY = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
AES_KEY  = hashlib.md5(SIGN_KEY[:16]).digest()   # 8252970d959b06db102e17d85c0ec1af
AES_IV   = hashlib.md5(SIGN_KEY[16:]).digest()   # 4d207ea37a419f7d622f81c6a2f53594


def decrypt_outer(xargus_b64: str) -> bytes:
    """base64 X-Argus -> AES-CBC-decrypted plaintext (rb01 stripped). No pkcs7."""
    raw = base64.b64decode(xargus_b64)
    rb01, ct = raw[:2], raw[2:]
    if len(ct) % 16:
        raise ValueError("ciphertext not block-aligned (len=%d)" % len(ct))
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ct)


def looks_valid(pt: bytes) -> bool:
    """The OUTER plaintext header signature for this build."""
    return len(pt) >= 9 and pt[0] == 0xEC and pt[5] == 0x01 and pt[8] == 0x18


# One real device capture (mobile/frida/out/passport/pas_1_req.txt) for the self-test.
_GENUINE = ("I1M14UQs3aAUT9y6uC3/V6+fimT06E9oUMxB30t1z7JuO7Ih2S/7pqDKyWMSwxeNU4ft3uWLG61gH0LUxDG"
            "cyykqba8jYP5k/06A2mGQqN40bQl2Pu8qIKCSMzSDDi8JNtAcK66ee+cFgMNQRdozzU+ZHayei+W0eONqpn"
            "dgF1ep65qO92EhSn4U5IF7tmb9TAqz8fX3qkTBg4i3O8RZCujm4Q+WEuFcs0sIS7ZeR8dS3RBdtLjn/bsSD"
            "LptgWYw0PyZFP63wBvSMSh54hFW1udVFDoux2QiBO1y3i+UJp9RSn3vJxonO0TJ+jcfV8c1zatESkyIO4BE"
            "7nP6OEzTb7M9PoOd/LcJ7X7otnHwF2hYJ6vTXJkbhgPyhwXkvKnl49DUwwCqOi+QHbhNHpVc4g1QREvAZXL"
            "NpVrQqG3N9eaO6y93dLQAHKZGNvGXQ4OidKbSz0gzzONy77tpMa2E8YbCeDl7VQPLWKRxFampqFrsE+qR5i"
            "2p4dxJlzzCpwtqH3IwMMWewr/Bm2OjTpsPX4H3GyJ40AKfuTkviOUgbKQL3mcXhppLT0SISb1DVIKAyiMxs"
            "ykzS8LAeTsvLO9P/UjkzXgbPPUAYU40dsEjkI7W9yCo8r3RHH2h0EGJzYlTeKyZucB3qWAuM5GIiulAtocR")


if __name__ == "__main__":
    print("AES_KEY = md5(sign_key[:16]) =", AES_KEY.hex())
    print("AES_IV  = md5(sign_key[16:]) =", AES_IV.hex())
    if len(sys.argv) > 1:
        pt = decrypt_outer(sys.argv[1])
        print("plaintext len =", len(pt), "valid-header =", looks_valid(pt))
        print("plaintext hex =", pt.hex())
    else:
        pt = decrypt_outer(_GENUINE)
        print("[self-test] genuine sample -> PT[:16] =", pt[:16].hex(),
              "| header-valid =", looks_valid(pt))
        assert looks_valid(pt), "self-test FAILED"
        print("[self-test] PASS")

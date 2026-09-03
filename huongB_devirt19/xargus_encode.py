#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xargus_encode.py — offline X-Argus ENCODER (report -> X-Argus b64), inverse of xargus_decode.py.

Inverts every stage of the VERIFIED decoder (xargus_decode.py):

  report (protobuf)
    -> simct = Simon128/256-ENCODE(report, key = SM3(SESSION_PSK + rb + SESSION_PSK)[:32])
    -> region = reverse( xa[8] || [ simct[j] ^ xa[(j+8)%4] ] )      # inverse reverse-XOR framing
    -> PT     = header[9] || region || tail[15]     (rb23 = tail[0:2], marker PT[-1]=0x0d)
    -> ct     = AES-128-CBC-enc(PT, aes_key, aes_iv)                # OUTER (stable license PSK)
    -> X-Argus = base64( rb01[2] || ct )

Correctness is proven by ROUND-TRIP against a genuine device capture: decode a real X-Argus,
capture its framing constants (header/tail/xa), re-encode, and assert the b64 is bit-identical.
This isolates the crypto/framing inversion (proven here) from report-protobuf construction.

Depends on the same modules as xargus_decode.py (gmssl SM3, community SIMON, native rotate_left).
"""
import sys, os, base64, hashlib, struct
from Crypto.Cipher import AES

_MOBILE = None
for cand in (os.path.join(os.path.dirname(__file__), "..", "..", "tiktok_signer", "mobile", "_websign", "armxe", "Mobile"),
             "/e/tiktok_signer/mobile/_websign/armxe/Mobile",
             r"E:\tiktok_signer\mobile\_websign\armxe\Mobile"):
    if os.path.isdir(cand):
        _MOBILE = cand; break
if _MOBILE:
    sys.path.insert(0, _MOBILE)
from gmssl import sm3           # noqa: E402
from cipher.SIMON import SIMON  # noqa: E402
from native import rotate_left  # noqa: E402

MASK = 0xFFFFFFFFFFFFFFFF
SIGN_KEY = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
AES_KEY = hashlib.md5(SIGN_KEY[:16]).digest()
AES_IV = hashlib.md5(SIGN_KEY[16:]).digest()
HDR, TAIL = 9, 15


def _sm3(b):
    return bytes.fromhex(sm3.sm3_hash(list(b)))


def _simon_encode(block2, kl):
    """Forward Simon128/256 — exact inverse of xargus_decode._simon_decode."""
    key = SIMON.key_expansion(kl + [0] * 68)
    a, b = block2[0] & MASK, block2[1] & MASK
    for i in range(0, 72):
        fb = ((rotate_left(b, 1) & rotate_left(b, 8)) ^ rotate_left(b, 2)) & MASK
        a, b = b, (a ^ fb ^ key[i]) & MASK
    return a, b


def simon_encrypt(report: bytes, kl) -> bytes:
    """Encrypt 16-byte-aligned report with Simon128/256 -> simct."""
    if len(report) % 16:
        raise ValueError("report not 16-aligned (%d)" % len(report))
    out = bytearray()
    for i in range(0, len(report), 16):
        a, b = _simon_encode(list(struct.unpack("<QQ", report[i:i + 16])), kl)
        out += struct.pack("<QQ", a, b)
    return bytes(out)


def frame_encode(simct: bytes, xa: bytes) -> bytes:
    """
    Inverse of the decoder's reverse-XOR framing.

    Decoder does:  xored = reverse(region); xa = xored[:8];
                   for i>=8: p[i] ^= xa[i%4]; simct = p[8:]
    So:  xored = xa || [ simct[i-8] ^ xa[i%4] for i in 8..len ];  region = reverse(xored)
    """
    if len(xa) != 8:
        raise ValueError("xa must be 8 bytes")
    xored = bytearray(xa)
    for j, c in enumerate(simct):
        i = j + 8
        xored.append(c ^ xa[i % 4])
    return bytes(xored[::-1])


def encode_xargus(report: bytes, rb01: bytes, tail: bytes, xa: bytes,
                  header: bytes = None, session_psk: bytes = SIGN_KEY) -> str:
    """
    Build an X-Argus b64 from a protobuf report + framing constants.

    rb01  : 2-byte outer header (also feeds Simon key as rb = rb01 + rb23)
    tail  : 15-byte trailer; tail[0:2] = rb23, tail[-1] = 0x0d marker
    xa    : 8-byte reverse-XOR array (nonce prefix of reversed region)
    header: 9-byte header (default: ec 00 00 00 00 01 00 00 18)
    """
    if header is None:
        header = bytes([0xec, 0, 0, 0, 0, 0x01, 0, 0, 0x18])
    rb23 = tail[0:2]
    rb = rb01 + rb23
    kl = list(struct.unpack("<QQQQ", _sm3(session_psk + rb + session_psk)[:32]))
    simct = simon_encrypt(report, kl)
    region = frame_encode(simct, xa)
    pt = header + region + tail
    ct = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pt)
    return base64.b64encode(rb01 + ct).decode()


# ---- round-trip proof against a genuine capture --------------------------------

def _extract_framing(xargus_b64, session_psk=SIGN_KEY):
    """Decode a genuine X-Argus and pull out (report, rb01, tail, xa, header)."""
    from xargus_decode import decode_xargus
    raw = base64.b64decode(xargus_b64)
    rb01, ct = raw[:2], raw[2:]
    pt = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ct)
    header = pt[:HDR]
    tail = pt[-TAIL:]
    region = pt[HDR:len(pt) - TAIL]
    xored = region[::-1]
    xa = xored[:8]
    report = decode_xargus(xargus_b64, session_psk)
    return report, rb01, tail, xa, header


def roundtrip_test():
    from xargus_outer import _GENUINE
    report, rb01, tail, xa, header = _extract_framing(_GENUINE)
    print("[rt] report len =", len(report), "| rb01 =", rb01.hex(),
          "| tail =", tail.hex(), "| xa =", xa.hex())

    rebuilt = encode_xargus(report, rb01, tail, xa, header)
    print("[rt] genuine  b64[:48] =", _GENUINE[:48])
    print("[rt] rebuilt  b64[:48] =", rebuilt[:48])

    match = (rebuilt == _GENUINE)
    print("[rt] EXACT MATCH =", match)
    assert match, "ROUND-TRIP FAILED - encoder does not invert decoder bit-exactly"
    print("[rt] PASS - encoder inverts decoder bit-exactly")
    return match


if __name__ == "__main__":
    roundtrip_test()

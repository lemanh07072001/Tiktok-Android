#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xargus_decode.py — FULL offline X-Argus decoder for TikTok musically 45.5.4
                   (libmetasec_ov.so md5 02f47578). OUTER + INNER, no phone.

Envelope (fully reversed + verified in unidbg harness AND on 13 genuine device captures):

  X-Argus (b64)
    -> raw = b64decode ; rb01 = raw[:2] ; ct = raw[2:]
    -> PT  = AES-128-CBC-dec(ct, aes_key, aes_iv)            # 272B for a thin sign; NO pkcs7
         aes_key = md5(SIGN_KEY[:16]) ; aes_iv = md5(SIGN_KEY[16:])
    -> rb23 = PT[-15:-13]  ;  rb = rb01 + rb23
    -> region  = PT[9:-15]                                    # strip 9B header + 15B tail
    -> simct   = reverse(region); xa=simct[:8]; simct[i>=8]^=xa[i%4]; simct=simct[8:]   # reverse-XOR
    -> report  = Simon128/256-decode(simct, key=SM3(SIGN_KEY + rb + SIGN_KEY)[:32])     # protobuf
       report[0:] = 08 d2 a4 80 82 04 ...  (field1 = argus magic 1077940818)

SIGN_KEY (build constant for this app version) = the metasec PSK material:
  c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163

Depends on the vendored community modules under mobile/_websign/armxe/Mobile (SIMON, native)
and gmssl (pip install gmssl) for SM3.
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
ARGUS_MAGIC = 0x20200929  # report field1 == ARGUS_MAGIC<<1 == 1077940818
SIGN_KEY = bytes.fromhex("c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163")
AES_KEY = hashlib.md5(SIGN_KEY[:16]).digest()
AES_IV = hashlib.md5(SIGN_KEY[16:]).digest()

# framing constants (offline-reversed; overhead = 9 header + 8 xor-array + 15 tail = 32 bytes)
HDR, TAIL = 9, 15


def _sm3(b): return bytes.fromhex(sm3.sm3_hash(list(b)))


def _simon_decode(block2, kl):
    key = SIMON.key_expansion(kl + [0] * 68)
    a, b = block2[0] & MASK, block2[1] & MASK
    for i in range(71, -1, -1):
        fa = ((rotate_left(a, 1) & rotate_left(a, 8)) ^ rotate_left(a, 2)) & MASK
        a, b = (b ^ fa ^ key[i]) & MASK, a
    return a, b


def decode_xargus(xargus_b64: str, session_psk: bytes = SIGN_KEY) -> bytes:
    """
    OUTER AES key/iv come from the STABLE license PSK (SIGN_KEY = c02f250f, build-const).
    INNER Simon key comes from the per-session SESSION_PSK (`session_psk`):
      - bootstrap window: session_psk == SIGN_KEY (default) -> decodes offline, no capture.
      - after a session/login refresh the app re-derives SESSION_PSK (keva triplet update);
        capture it live (SM3 0xa0748 hook: block = SESSION_PSK||rb||SESSION_PSK) and pass here.
    """
    raw = base64.b64decode(xargus_b64)
    rb01, ct = raw[:2], raw[2:]
    pt = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(ct)      # OUTER (stable license PSK)
    rb = rb01 + pt[-TAIL:-TAIL + 2]                              # rb01 + rb23
    region = pt[HDR:len(pt) - TAIL]
    xored = region[::-1]
    xa = xored[:8]
    p = bytearray(xored)
    for i in range(8, len(p)):
        p[i] ^= xa[i % 4]
    simct = bytes(p[8:])
    if len(simct) % 16:
        raise ValueError("simon ciphertext not 16-aligned (%d) — framing/length differs" % len(simct))
    kl = list(struct.unpack("<QQQQ", _sm3(session_psk + rb + session_psk)[:32]))
    out = bytearray()
    for i in range(0, len(simct), 16):
        a, b = _simon_decode(list(struct.unpack("<QQ", simct[i:i + 16])), kl)
        out += struct.pack("<QQ", a, b)
    return bytes(out)


def check_magic(report: bytes):
    if not report or report[0] != 0x08:
        return False, None
    v = s = 0
    i = 1
    while i < len(report) and i < 11:
        c = report[i]; v |= (c & 0x7f) << s; i += 1; s += 7
        if not c & 0x80:
            break
    return v == (ARGUS_MAGIC << 1), v


def _summary(report: bytes) -> str:
    asc = "".join(chr(c) if 32 <= c < 127 else "." for c in report)
    return asc[:100]


if __name__ == "__main__":
    if len(sys.argv) > 1:
        rep = decode_xargus(sys.argv[1])
        ok, magic = check_magic(rep)
        print("magic OK =", ok, "(field1 =", magic, ")")
        print("report len =", len(rep))
        print("head =", rep[:48].hex())
        print("ascii =", _summary(rep))
    else:
        print("usage: python xargus_decode.py <x-argus-b64>")

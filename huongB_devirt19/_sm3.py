#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# _sm3.py — stock SM3 (GB/T 32905-2016), self-contained. KAT: sm3(b'abc') ==
#   66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
# Matches libmetasec_ov.so SM3 fn @0xa0748 (note 33): the .so keeps state little-endian
# internally and byte-swaps each word on output; that byte-swapped value == this standard
# big-endian digest, so stock SM3 is correct.

_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
       0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
_M = 0xffffffff


def _rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _M


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _cf(V, B):
    W = [0] * 68
    for i in range(16):
        W[i] = int.from_bytes(B[4 * i:4 * i + 4], "big")
    for j in range(16, 68):
        W[j] = (_p1(W[j - 16] ^ W[j - 9] ^ _rotl(W[j - 3], 15))
                ^ _rotl(W[j - 13], 7) ^ W[j - 6]) & _M
    W1 = [(W[j] ^ W[j + 4]) & _M for j in range(64)]
    A, Bb, C, D, E, F, G, H = V
    for j in range(64):
        T = 0x79cc4519 if j < 16 else 0x7a879d8a
        SS1 = _rotl((_rotl(A, 12) + E + _rotl(T, j)) & _M, 7)
        SS2 = SS1 ^ _rotl(A, 12)
        if j < 16:
            FF = A ^ Bb ^ C
            GG = E ^ F ^ G
        else:
            FF = (A & Bb) | (A & C) | (Bb & C)
            GG = (E & F) | ((~E & _M) & G)
        TT1 = (FF + D + SS2 + W1[j]) & _M
        TT2 = (GG + H + SS1 + W[j]) & _M
        D = C
        C = _rotl(Bb, 9)
        Bb = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _p0(TT2)
    return [(a ^ b) & _M for a, b in zip(V, [A, Bb, C, D, E, F, G, H])]


def sm3(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += ml.to_bytes(8, "big")
    V = _IV[:]
    for i in range(0, len(msg), 64):
        V = _cf(V, msg[i:i + 64])
    return b"".join(x.to_bytes(4, "big") for x in V)


if __name__ == "__main__":
    kat = sm3(b"abc").hex()
    assert kat == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", kat
    # second KAT (512-bit "abcd"*16)
    kat2 = sm3(b"abcd" * 16).hex()
    assert kat2 == "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", kat2
    print("SM3 KAT PASS")

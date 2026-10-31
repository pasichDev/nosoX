"""Independent test-only affine secp256k1 equations; no production signing.

Public, deliberately trivial x=1 and nonce=2. This is NOT a wallet or a
cryptographic library. Used solely to reproduce known-answer test constants.
"""
import hashlib
import json

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, P) if a == b else
             (v-y) * pow(u-x, -1, P)) % P
    z = (slope*slope-x-u) % P
    return z, (slope*(x-z)-y) % P


def mul(k, a):
    result = None
    while k:
        if k & 1:
            result = add(result, a)
        a = add(a, a)
        k >>= 1
    return result


def enc(a):
    return bytes([2 + a[1] % 2]) + a[0].to_bytes(32, 'big')


x = int.from_bytes(hashlib.sha256(b'NosoX/pedersen-h/v5\x00').digest(), 'big') % P
while True:
    rhs = (x*x*x+7) % P
    y = pow(rhs, (P+1)//4, P)
    if y*y % P == rhs:
        H = x, y if y % 2 == 0 else P-y
        break
    x = (x+1) % P
msg = b'NosoX independent arithmetic vector'
r = enc(mul(2, G))
pub = enc(G)
e = int.from_bytes(hashlib.sha256(b'NosoX/schnorr/v5\x00'+r+pub+
                                 len(msg).to_bytes(4, 'big')+msg).digest(), 'big') % N
signature = r + ((2+e) % N).to_bytes(32, 'big')
print(json.dumps({'H': enc(H).hex(), 'C_42_1': enc(add(mul(42,H),G)).hex(),
                  'public':pub.hex(), 'message':msg.decode(),
                  'signature':signature.hex()}, indent=2))

import hashlib, os, random
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
p = 2**255 - 19
def x25519(k, u):
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, 'little'); u = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1; swap ^= kt
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A = x2 + z2; AA = A*A; B = x2 - z2; BB = B*B; E = AA - BB; C = x3 + z3; D = x3 - z3
        DA = D*A; CB = C*B
        x3 = (DA + CB)**2 % p; z3 = x1*(DA - CB)**2 % p; x2 = AA*BB % p; z2 = E*(AA + 121665*E) % p
    if swap: x2, z2 = x3, z3
    return (x2 * pow(z2, p-2, p) % p).to_bytes(32, 'little')
def ke(prv64, pub):
    y = int.from_bytes(pub, 'little') & ((1 << 255) - 1)
    u = (1 + y) * pow((1 - y) % p, p-2, p) % p
    return x25519(prv64[:32], u.to_bytes(32, 'little'))

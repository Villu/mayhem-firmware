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
random.seed(7)
out = []
ids = []
for n in range(6):
    seed = bytes(random.randrange(256) for _ in range(32))
    key = ECC.construct(curve='ed25519', seed=seed)
    pub = key.public_key().export_key(format='raw')
    prv = hashlib.sha512(seed).digest()
    msg = bytes(random.randrange(256) for _ in range(random.choice([0, 1, 37, 111, 128, 200])))
    sig = eddsa.new(key, 'rfc8032').sign(msg)
    ids.append((prv, pub))
    out.append(f'{{"{prv.hex()}", "{pub.hex()}", "{msg.hex()}", "{sig.hex()}"}}')
print("// prv64, pub, msg, sig  (pycryptodome Ed25519)")
print("static const char* const ED_VEC[][4] = {\n    " + ",\n    ".join(out) + "};")
ke_out = []
for i in range(0, 6, 2):
    (pa, ua), (pb, ub) = ids[i], ids[i+1]
    s1 = ke(pa, ub); s2 = ke(pb, ua); assert s1 == s2
    ke_out.append(f'{{{i}, {i+1}, "{s1.hex()}"}}')
print("// shared secret (pure-Python X25519 of the Montgomery-mapped key), both sides agree")
print("struct KeVec { int a, b; const char* shared; };")
print("static const KeVec KE_VEC[] = {" + ", ".join(ke_out) + "};")

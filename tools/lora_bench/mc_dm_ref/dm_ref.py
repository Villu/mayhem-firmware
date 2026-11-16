import hashlib, struct, random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from edlib import ke
def seal(secret, plain):
    plain = plain + bytes(-len(plain) % 16)
    ct = AES.new(secret[:16], AES.MODE_ECB).encrypt(plain)
    return HMAC.new(secret, ct, SHA256).digest()[:2] + ct
random.seed(11)
seeds = [bytes(random.randrange(256) for _ in range(32)) for _ in range(2)]
keys = [ECC.construct(curve='ed25519', seed=s) for s in seeds]
pubs = [k.public_key().export_key(format='raw') for k in keys]
prvs = [hashlib.sha512(s).digest() for s in seeds]
assert all(p[0] not in (0, 255) for p in pubs)
L = []
L.append(f'static const char* const DM_PRV_A = "{prvs[0].hex()}";')
L.append(f'static const char* const DM_PRV_B = "{prvs[1].hex()}";')
# advert by A
ts = 1763300000; name = "PortaPack"
app = bytes([0x81]) + name.encode()
sig = eddsa.new(keys[0], 'rfc8032').sign(pubs[0] + struct.pack('<I', ts) + app)
adv = bytes([0x11, 0]) + pubs[0] + struct.pack('<I', ts) + sig + app
L.append(f'static const char* const DM_ADVERT_A = "{adv.hex()}";  // ts {ts}, "{name}"')
secret = ke(prvs[0], pubs[1])
assert secret == ke(prvs[1], pubs[0])
L.append(f'static const char* const DM_SECRET = "{secret.hex()}";')
# A -> B text, attempt 1
text = "Hello from the PortaPack, a direct message"
plain = struct.pack('<I', ts + 5) + bytes([1]) + text.encode()
ack = hashlib.sha256(plain + pubs[0]).digest()[:4]
pkt = bytes([(2 << 2) | 1, 0, pubs[1][0], pubs[0][0]]) + seal(secret, plain)
L.append(f'static const char* const DM_TEXT_AB = "{pkt.hex()}";  // ts {ts+5}, attempt 1')
L.append(f'static const char* const DM_TEXT_AB_ACK = "{ack.hex()}";')
L.append(f'static const char* const DM_TEXT = "{text}";')
# B answers with a path return carrying the ACK, as if the text came via 2 repeaters (hashes 0x5a, 0xc3)
plainp = bytes([2, 0x5a, 0xc3, 3]) + ack
pp = bytes([(8 << 2) | 1, 0, pubs[0][0], pubs[1][0]]) + seal(secret, plainp)
L.append(f'static const char* const DM_PATH_BA = "{pp.hex()}";')
ackpkt = bytes([(3 << 2) | 1, 0]) + ack
L.append(f'static const char* const DM_ACK = "{ackpkt.hex()}";')
open('dm_vectors.inc', 'w').write("\n".join(L) + "\n")
print("\n".join(L))

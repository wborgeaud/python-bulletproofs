from utils import mod_hash, point_to_bytes, inner_product, ModP
from inner_product_prover import NIProver
from inner_product_verifier import Verifier1
from commitments import vector_commitment
from elliptic_curve_hash import elliptic_hash
from ecdsa import SECP256k1
from pippenger import Pippenger, EC
import time

SUPERCURVE = SECP256k1
CURVE = SUPERCURVE.curve
p = SUPERCURVE.order

N = 128

g = [elliptic_hash(str(i).encode() + b'This', CURVE) for i in range(N)]
h = [elliptic_hash(str(i).encode() + b'is', CURVE) for i in range(N)]
u = elliptic_hash(b'a test', CURVE)

a = [mod_hash(str(i).encode() + b'testing', p) for i in range(N)]
b = [mod_hash(str(i).encode() + b'still testing', p) for i in range(N)]

P = vector_commitment(g, h, a, b)
c = inner_product(a, b)

Prov = NIProver(g, h, u, P, c, a, b, SECP256k1, True)
proof = Prov.prove()
Verif = Verifier1(g, h, u, P, c, proof)

print(Verif.verify())

# print(pTranscript)
# print(len(pTranscript))
# print(len(hex(int(pTranscript))))
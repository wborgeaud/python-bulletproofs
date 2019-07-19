"""Various tests"""

from ecdsa import SECP256k1
from .utils.utils import mod_hash, inner_product
from .innerproduct.inner_product_prover import NIProver
from .innerproduct.inner_product_verifier import Verifier1
from .utils.commitments import vector_commitment
from .utils.elliptic_curve_hash import elliptic_hash

SUPERCURVE = SECP256k1
CURVE = SUPERCURVE.curve
p = SUPERCURVE.order

N = 2

seeds = [
    b"\xad\xa87\xfcn\xdd_X\xbf\xf2",
    b"\xac]\xed\x01\xe6T\xb9rl\x06",
    b"\x94,\xbf\\\xdf\x02}\xdf\xa7\x12",
    b"2O\x06W\xaa\xb5\x8a\xdc\xaf\xb4",
    b"\rW\x9e\x136@K\xb1\x08\x8c",
    b"\xe3\xd9E\x9e&\xfd<\x82S\x0c",
]

g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
u = elliptic_hash(seeds[2], CURVE)
a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
P = vector_commitment(g, h, a, b)
c = inner_product(a, b)
Prov = NIProver(g, h, u, P, c, a, b, SECP256k1, seeds[5])
proof = Prov.prove()
Verif = Verifier1(g, h, u, P, c, proof)

print(Verif.verify())

print(len(proof.transcript))
print(len(proof.proof2.transcript))
print(proof.transcript)
print(proof.proof2.transcript)

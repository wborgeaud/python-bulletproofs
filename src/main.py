"""Various tests"""

from ecdsa import SECP256k1
import os
from .utils.utils import mod_hash, inner_product
from .innerproduct.inner_product_prover import NIProver, FastNIProver2
from .innerproduct.inner_product_verifier import Verifier1, Verifier2
from .utils.commitments import vector_commitment
from .utils.elliptic_curve_hash import elliptic_hash

SUPERCURVE = SECP256k1
CURVE = SUPERCURVE.curve
p = SUPERCURVE.order

seeds = [os.urandom(10) for _ in range(6)]
p = SUPERCURVE.order
N = 16
g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
u = elliptic_hash(seeds[2], CURVE)
a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
P = vector_commitment(g, h, a, b) + inner_product(a, b) * u
Prov = FastNIProver2(g, h, u, P, a, b, SUPERCURVE)
proof = Prov.prove()
Verif = Verifier2(g, h, u, 2*P, proof)
Verif.verify()
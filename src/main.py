"""Various tests"""

from ecdsa import SECP256k1
import os
from .utils.utils import mod_hash, inner_product, ModP
from .utils.commitments import vector_commitment, commitment
from .utils.elliptic_curve_hash import elliptic_hash
from .rangeproofs.rangeproof_prover import NIRangeProver
from .rangeproofs.rangeproof_verifier import RangeVerifier

SUPERCURVE = SECP256k1
CURVE = SUPERCURVE.curve
p = SUPERCURVE.order

seeds = [os.urandom(10) for _ in range(7)]
v, n = ModP(15,p), 16
gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
g = elliptic_hash(seeds[2], CURVE)
h = elliptic_hash(seeds[3], CURVE)
u = elliptic_hash(seeds[4], CURVE)
gamma = mod_hash(seeds[5],p)

V = commitment(g,h,v,gamma)


Prov = NIRangeProver(v,n,g,h,gs,hs,gamma,u,SUPERCURVE,seeds[6])
proof = Prov.prove()
Verif = RangeVerifier(V,g,h,gs,hs,u,proof)
Verif.verify()
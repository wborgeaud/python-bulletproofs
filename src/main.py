"""Various tests"""

from ecdsa import SECP256k1
import os
from .utils.utils import mod_hash, inner_product, ModP
from .utils.commitments import vector_commitment, commitment
from .utils.elliptic_curve_hash import elliptic_hash

# from .rangeproofs.rangeproof_prover import NIRangeProver
# from .rangeproofs.rangeproof_verifier import RangeVerifier
from .rangeproofs.rangeproof_aggreg_prover import AggregNIRangeProver
from .rangeproofs.rangeproof_aggreg_verifier import AggregRangeVerifier


SUPERCURVE = SECP256k1
CURVE = SUPERCURVE.curve
p = SUPERCURVE.order

# seeds = [os.urandom(10) for _ in range(7)]
# v, n = ModP(15,p), 16
# gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
# hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
# g = elliptic_hash(seeds[2], CURVE)
# h = elliptic_hash(seeds[3], CURVE)
# u = elliptic_hash(seeds[4], CURVE)
# gamma = mod_hash(seeds[5],p)

# V = commitment(g,h,v,gamma)


# Prov = NIRangeProver(v,n,g,h,gs,hs,gamma,u,SUPERCURVE,seeds[6])
# proof = Prov.prove()
# Verif = RangeVerifier(V,g,h,gs,hs,u,proof)
# Verif.verify()
m = 4
seeds = [os.urandom(10) for _ in range(7)]
vs, n = [ModP(15, p) for _ in range(m)], 16
vs[-1] = ModP(2 ** 16 - 1, p)
gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n * m)]
hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n * m)]
g = elliptic_hash(seeds[2], CURVE)
h = elliptic_hash(seeds[3], CURVE)
u = elliptic_hash(seeds[4], CURVE)
gammas = [mod_hash(seeds[5], p) for _ in range(m)]

Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]


Prov = AggregNIRangeProver(vs, n, g, h, gs, hs, gammas, u, SUPERCURVE, seeds[6])
proof = Prov.prove()
Verif = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
Verif.verify()

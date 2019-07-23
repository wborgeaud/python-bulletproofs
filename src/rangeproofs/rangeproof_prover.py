from typing import List
from ..utils.utils import Point, ModP, inner_product, mod_hash
from ..utils.transcript import Transcript
from ..utils.commitments import vector_commitment, commitment
from .rangeproof_verifier import Proof
from ..innerproduct.inner_product_prover import NIProver
from ..pippenger import PipSECP256k1


class NIRangeProver:
    def __init__(
        self,
        v: ModP,
        n: int,
        g: Point,
        h: Point,
        gs: List[Point],
        hs: List[Point],
        gamma: ModP,
        u: Point,
        group,
        seed: bytes = b"",
    ):
        self.v = v
        self.n = n
        self.g = g
        self.h = h
        self.gs = gs
        self.hs = hs
        self.gamma = gamma
        self.u = u
        self.group = group
        self.transcript = Transcript(seed)

    def prove(self):
        v = self.v
        n = self.n
        gs = self.gs
        hs = self.hs
        h = self.h

        aL = list(map(int, reversed(bin(v.x)[2:].zfill(n))))[:n]
        aR = [
            (x - 1) % self.group.q for x in aL
        ]  # TODO implement inverse of elliptic curve point  to compute -1 * g instead of multiplying by p-1
        alpha = mod_hash(b"alpha" + self.transcript.digest, self.group.q)
        A = vector_commitment(gs, hs, aL, aR) + alpha * h
        sL = [
            mod_hash(str(i).encode() + self.transcript.digest, self.group.q)
            for i in range(n)
        ]
        sR = [
            mod_hash(str(i).encode() + self.transcript.digest, self.group.q)
            for i in range(n, 2 * n)
        ]
        rho = mod_hash(str(2 * n).encode() + self.transcript.digest, self.group.q)
        S = vector_commitment(gs, hs, sL, sR) + rho * h
        self.transcript.add_list_points([A, S])
        y = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(y)
        z = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(z)

        t1, t2 = self._get_polynomial_coeffs(aL, aR, sL, sR, y, z)
        tau1 = mod_hash(b"tau1" + self.transcript.digest, self.group.q)
        tau2 = mod_hash(b"tau2" + self.transcript.digest, self.group.q)
        T1 = commitment(self.g, h, t1, tau1)
        T2 = commitment(self.g, h, t2, tau2)
        self.transcript.add_list_points([T1, T2])
        x = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(x)
        taux, mu, t_hat, ls, rs = self._final_compute(
            aL, aR, sL, sR, y, z, x, tau1, tau2, alpha, rho
        )

        # return Proof(taux, mu, t_hat, ls, rs, T1, T2, A, S), x,y,z
        hsp = [(y.inv() ** i) * hs[i] for i in range(n)]
        P = (
            A
            + x * S
            + PipSECP256k1.multiexp(
                gs + hsp,
                [-z for _ in range(n)]
                + [(z * (y ** i)) + ((z ** 2) * (2 ** i)) for i in range(n)],
            )
        )

        InnerProv = NIProver(gs, hsp, self.u, P + (-mu) * h, t_hat, ls, rs, self.group)
        innerProof = InnerProv.prove()

        return Proof(taux, mu, t_hat, T1, T2, A, S, innerProof, self.transcript.digest)

    def _get_polynomial_coeffs(self, aL, aR, sL, sR, y, z):
        t1 = inner_product(
            sL, [(y ** i) * (aR[i] + z) + (z ** 2) * (2 ** i) for i in range(self.n)]
        ) + inner_product(
            [aL[i] - z for i in range(self.n)],
            [(y ** i) * sR[i] for i in range(self.n)],
        )
        t2 = inner_product(sL, [(y ** i) * sR[i] for i in range(self.n)])
        return t1, t2

    def _final_compute(self, aL, aR, sL, sR, y, z, x, tau1, tau2, alpha, rho):
        ls = [aL[i] - z + sL[i] * x for i in range(self.n)]
        rs = [
            (y ** i) * (aR[i] + z + sR[i] * x) + (z ** 2) * (2 ** i)
            for i in range(self.n)
        ]
        t_hat = inner_product(ls, rs)
        taux = tau2 * (x ** 2) + tau1 * x + (z ** 2) * self.gamma
        mu = alpha + rho * x
        return taux, mu, t_hat, ls, rs

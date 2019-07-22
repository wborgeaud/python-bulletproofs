from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

from ..utils.utils import inner_product, ModP
from ..utils.commitments import vector_commitment

SUPERCURVE = SECP256k1


class Proof:
    """Proof class for Protocol 1"""

    def __init__(self, taux, mu, t_hat, ls, rs, T1, T2, A, S):
        self.taux = taux
        self.mu = mu
        self.t_hat = t_hat
        self.ls = ls
        self.rs = rs
        self.T1 = T1
        self.T2 = T2
        self.A = A
        self.S = S


class RangeVerifier:
    """Verifier class for Protocol 1"""

    def __init__(self, V, g, h, gs, hs, x, y, z, proof: Proof):
        self.V = V
        self.g = g
        self.h = h
        self.gs = gs
        self.hs = hs
        self.x = x
        self.y = y
        self.z = z
        self.proof = proof

    def assertThat(self, expr: bool):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        pass

    def verify(self):
        """Verifies the proof given by a prover. Raises an execption if it is invalid"""
        self.verify_transcript()

        g = self.g
        h = self.h
        gs = self.gs
        hs = self.hs
        x = self.x
        y = self.y
        z = self.z
        proof = self.proof

        n = len(gs)
        delta_yz = (z - z ** 2) * sum(
            [y ** i for i in range(n)], ModP(0, SUPERCURVE.order)
        ) - (z ** 3) * ModP(2 ** n - 1, SUPERCURVE.order)
        hsp = [(y.inv() ** i) * hs[i] for i in range(n)]
        self.assertThat(
            proof.t_hat * g + proof.taux * h
            == (z ** 2) * self.V + delta_yz * g + x * proof.T1 + (x ** 2) * proof.T2
        )

        P = self._getP(x, y, z, proof.A, proof.S, gs, hsp, n)
        self.assertThat(
            P == vector_commitment(gs, hsp, proof.ls, proof.rs) + proof.mu * h
        )
        self.assertThat(proof.t_hat == inner_product(proof.ls, proof.rs))

    def _getP(self, x, y, z, A, S, gs, hsp, n):
        return (
            A
            + x * S
            + sum([(-z) * gs[i] for i in range(n)], Point(None, None, None))
            + sum(
                [((z * (y ** i)) + ((z ** 2) * (2 ** i))) * hsp[i] for i in range(n)],
                Point(None, None, None)
            )
        )
from fastecdsa.curve import secp256k1

from ..utils.utils import ModP, point_to_b64
from ..innerproduct.inner_product_verifier import Verifier1
from ..pippenger import PipSECP256k1

CURVE = secp256k1


class Proof:
    """Proof class for Protocol 1"""

    def __init__(self, taux, mu, t_hat, T1, T2, A, S, innerProof, transcript):
        self.taux = taux
        self.mu = mu
        self.t_hat = t_hat
        self.T1 = T1
        self.T2 = T2
        self.A = A
        self.S = S
        self.innerProof = innerProof
        self.transcript = transcript


class AggregRangeVerifier:
    """Verifier class for Range Proofs"""

    def __init__(self, Vs, g, h, gs, hs, u, proof: Proof):
        self.Vs = Vs
        self.g = g
        self.h = h
        self.gs = gs
        self.hs = hs
        self.u = u
        self.proof = proof

    def assertThat(self, expr: bool):
        """Assert that expr is truthy else raise exception"""
        if not expr:
            raise Exception("Proof invalid")

    def verify_transcript(self):
        """Verify a transcript to assure Fiat-Shamir was done properly"""
        proof = self.proof
        p = proof.taux.p
        lTranscript = proof.transcript.split(b"&")
        self.assertThat(lTranscript[1] == point_to_b64(proof.A))
        self.assertThat(lTranscript[2] == point_to_b64(proof.S))
        self.y = ModP(int(lTranscript[3]), p)
        self.z = ModP(int(lTranscript[4]), p)
        self.assertThat(lTranscript[5] == point_to_b64(proof.T1))
        self.assertThat(lTranscript[6] == point_to_b64(proof.T2))
        self.x = ModP(int(lTranscript[7]), p)

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

        nm = len(gs)
        m = len(self.Vs)
        n = nm // m

        delta_yz = (z - z ** 2) * sum(
            [y ** i for i in range(nm)], ModP(0, CURVE.q)
        ) - sum(
            [
                (z ** (j + 2)) * ModP(2 ** n - 1, CURVE.q)
                for j in range(1, m + 1)
            ]
        )
        hsp = [(y.inv() ** i) * hs[i] for i in range(nm)]

        self.assertThat(
            proof.t_hat * g + proof.taux * h
            == PipSECP256k1.multiexp(
                self.Vs + [g, proof.T1, proof.T2],
                [z ** (j + 2) for j in range(m)] + [delta_yz, x, x ** 2],
            )
        )

        P = self._getP(x, y, z, proof.A, proof.S, gs, hsp, n, m)
        InnerVerif = Verifier1(
            gs, hsp, self.u, P + (-proof.mu) * h, proof.t_hat, proof.innerProof
        )
        return InnerVerif.verify()

    def _getP(self, x, y, z, A, S, gs, hsp, n, m):
        return (
            A
            + x * S
            + PipSECP256k1.multiexp(
                gs + hsp,
                [-z for _ in range(n * m)]
                + [
                    (z * (y ** i)) + (z ** (2 + (i // n))) * (2 ** (i % n))
                    for i in range(n * m)
                ],
            )
        )

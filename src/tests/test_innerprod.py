import unittest
import os
from random import randint
from ecdsa import SECP256k1
from ..inner_product_prover import NIProver
from ..inner_product_verifier import Verifier1
from ..commitments import vector_commitment
from ..utils import mod_hash, inner_product
from ..elliptic_curve_hash import elliptic_hash


SUPERCURVE = SECP256k1
CURVE = SUPERCURVE.curve


class InnerProductArgumentTest(unittest.TestCase):
    def test_different_seeds(self):
        for _ in range(20):
            seeds = [os.urandom(10) for _ in range(6)]
            p = SUPERCURVE.order
            N = 16
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
            with self.subTest(seeds=seeds):
                self.assertTrue(Verif.verify())

    def test_different_N(self):
        for i in range(9):
            seeds = [os.urandom(10) for _ in range(6)]
            p = SUPERCURVE.order
            N = 2 ** i
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
            with self.subTest(N=N, seeds=seeds):
                self.assertTrue(Verif.verify())

    def test_prover_cheating_false_c(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, P, c + 1, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_P(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, 2 * P, c, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_a(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        a[randint(0, N - 1)] *= 2
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, 2 * P, c, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_b(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        b[randint(0, N - 1)] *= 2
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, 2 * P, c, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_u(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        u *= 2
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, 2 * P, c, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_transcript1(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, 2 * P, c, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        randind = randint(0, len(proof.transcript) - 1)
        proof.transcript = (
            proof.transcript[:randind] + os.urandom(1) + proof.transcript[randind + 1 :]
        )
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()

    def test_prover_cheating_false_transcript2(self):
        seeds = [os.urandom(10) for _ in range(6)]
        p = SUPERCURVE.order
        N = 16
        g = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(N)]
        h = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(N)]
        u = elliptic_hash(seeds[2], CURVE)
        a = [mod_hash(str(i).encode() + seeds[3], p) for i in range(N)]
        b = [mod_hash(str(i).encode() + seeds[4], p) for i in range(N)]
        P = vector_commitment(g, h, a, b)
        c = inner_product(a, b)
        Prov = NIProver(g, h, u, 2 * P, c, a, b, SECP256k1, seeds[5])
        proof = Prov.prove()
        randind = randint(0, len(proof.proof2.transcript) - 1)
        proof.transcript = (
            proof.proof2.transcript[:randind]
            + os.urandom(1)
            + proof.proof2.transcript[randind + 1 :]
        )
        Verif = Verifier1(g, h, u, P, c, proof)
        with self.assertRaisesRegex(Exception, "Proof invalid"):
            Verif.verify()
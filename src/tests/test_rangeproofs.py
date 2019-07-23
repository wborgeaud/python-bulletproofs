import unittest
import os
from random import randint
from fastecdsa.curve import secp256k1
from ..innerproduct.inner_product_prover import NIProver, FastNIProver2
from ..innerproduct.inner_product_verifier import Verifier1, Verifier2
from ..utils.commitments import vector_commitment, commitment
from ..utils.utils import mod_hash, inner_product, ModP
from ..utils.elliptic_curve_hash import elliptic_hash
from ..rangeproofs import NIRangeProver, RangeVerifier


CURVE = secp256k1
p = CURVE.q


class RangeProofTest(unittest.TestCase):
    def test_different_seeds(self):
        for _ in range(10):
            seeds = [os.urandom(10) for _ in range(7)]
            v, n = ModP(randint(0, 2 ** 16 - 1), p), 16
            gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
            hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
            g = elliptic_hash(seeds[2], CURVE)
            h = elliptic_hash(seeds[3], CURVE)
            u = elliptic_hash(seeds[4], CURVE)
            gamma = mod_hash(seeds[5], p)
            V = commitment(g, h, v, gamma)
            Prov = NIRangeProver(v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
            proof = Prov.prove()
            Verif = RangeVerifier(V, g, h, gs, hs, u, proof)
            with self.subTest(seeds=seeds):
                self.assertTrue(Verif.verify())

    def test_different_n_and_v(self):
        for _ in range(3):
            for i in range(1, 8):
                seeds = [os.urandom(10) for _ in range(7)]
                v, n = ModP(randint(0, 2 ** (2 ** i) - 1), p), 2 ** i
                gs = [
                    elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)
                ]
                hs = [
                    elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)
                ]
                g = elliptic_hash(seeds[2], CURVE)
                h = elliptic_hash(seeds[3], CURVE)
                u = elliptic_hash(seeds[4], CURVE)
                gamma = mod_hash(seeds[5], p)
                V = commitment(g, h, v, gamma)
                Prov = NIRangeProver(v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
                proof = Prov.prove()
                Verif = RangeVerifier(V, g, h, gs, hs, u, proof)
                with self.subTest(v=v, n=n, seeds=seeds):
                    self.assertTrue(Verif.verify())

    def test_prover_cheating_false_v(self):
        seeds = [os.urandom(10) for _ in range(7)]
        v, n = ModP(randint(2**16,2**17), p), 16
        gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
        hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
        g = elliptic_hash(seeds[2], CURVE)
        h = elliptic_hash(seeds[3], CURVE)
        u = elliptic_hash(seeds[4], CURVE)
        gamma = mod_hash(seeds[5], p)
        V = commitment(g, h, v, gamma)
        Prov = NIRangeProver(v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        proof = Prov.prove()
        Verif = RangeVerifier(V, g, h, gs, hs, u, proof)
        with self.subTest(v=v, n=n):
            with self.assertRaisesRegex(Exception, "Proof invalid"):
                Verif.verify()

    def test_prover_cheating_false_commitment(self):
        seeds = [os.urandom(10) for _ in range(7)]
        v, n = ModP(randint(0,2**16), p), 16
        gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
        hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
        g = elliptic_hash(seeds[2], CURVE)
        h = elliptic_hash(seeds[3], CURVE)
        u = elliptic_hash(seeds[4], CURVE)
        gamma = mod_hash(seeds[5], p)
        V = commitment(g, h, v+1, gamma)
        Prov = NIRangeProver(v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        proof = Prov.prove()
        Verif = RangeVerifier(V, g, h, gs, hs, u, proof)
        with self.subTest(v=v, n=n):
            with self.assertRaisesRegex(Exception, "Proof invalid"):
                Verif.verify()

    def test_prover_cheating_false_transcript1(self):
        seeds = [os.urandom(10) for _ in range(7)]
        v, n = ModP(randint(0,2**16), p), 16
        gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n)]
        hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n)]
        g = elliptic_hash(seeds[2], CURVE)
        h = elliptic_hash(seeds[3], CURVE)
        u = elliptic_hash(seeds[4], CURVE)
        gamma = mod_hash(seeds[5], p)
        V = commitment(g, h, v+1, gamma)
        Prov = NIRangeProver(v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        proof = Prov.prove()
        while True:
            randind = randint(0, len(proof.transcript) - 1)
            new = str(randint(0,9)).encode()
            if proof.transcript[randind] not in [b'&', new]:
                proof.transcript = (
                    proof.transcript[:randind] + new + proof.transcript[randind + 1 :]
                )
                break
        Verif = RangeVerifier(V, g, h, gs, hs, u, proof)
        with self.subTest(v=v, n=n, randind=randind):
            with self.assertRaisesRegex(Exception, "Proof invalid"):
                Verif.verify()

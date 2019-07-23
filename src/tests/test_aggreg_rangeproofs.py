import unittest
import os
from random import randint
from fastecdsa.curve import secp256k1
from ..utils.commitments import commitment
from ..utils.utils import mod_hash, ModP
from ..utils.elliptic_curve_hash import elliptic_hash
from ..rangeproofs import AggregNIRangeProver, AggregRangeVerifier


CURVE = secp256k1
p = secp256k1.q


class AggregRangeProofTest(unittest.TestCase):
    def test_different_seeds(self):
        for _ in range(10):
            m = 4
            seeds = [os.urandom(10) for _ in range(7)]
            vs, n = [ModP(randint(0, 2 ** 16 - 1), p) for _ in range(m)], 16
            gs = [
                elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n * m)
            ]
            hs = [
                elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n * m)
            ]
            g = elliptic_hash(seeds[2], CURVE)
            h = elliptic_hash(seeds[3], CURVE)
            u = elliptic_hash(seeds[4], CURVE)
            gammas = [mod_hash(seeds[5], p) for _ in range(m)]
            Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]
            Prov = AggregNIRangeProver(
                vs, n, g, h, gs, hs, gammas, u, CURVE, seeds[6]
            )
            proof = Prov.prove()
            Verif = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
            with self.subTest(seeds=seeds, vs=vs):
                self.assertTrue(Verif.verify())

    def test_different_n_and_vs(self):
        for _ in range(3):
            for i in range(1, 8):
                m = 4
                seeds = [os.urandom(10) for _ in range(7)]
                vs, n = (
                    [ModP(randint(0, 2 ** (2 ** i) - 1), p) for _ in range(m)],
                    2 ** i,
                )
                gs = [
                    elliptic_hash(str(i).encode() + seeds[0], CURVE)
                    for i in range(n * m)
                ]
                hs = [
                    elliptic_hash(str(i).encode() + seeds[1], CURVE)
                    for i in range(n * m)
                ]
                g = elliptic_hash(seeds[2], CURVE)
                h = elliptic_hash(seeds[3], CURVE)
                u = elliptic_hash(seeds[4], CURVE)
                gammas = [mod_hash(seeds[5], p) for _ in range(m)]
                Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]
                Prov = AggregNIRangeProver(
                    vs, n, g, h, gs, hs, gammas, u, CURVE, seeds[6]
                )
                proof = Prov.prove()
                Verif = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
                with self.subTest(seeds=seeds, vs=vs, n=n):
                    self.assertTrue(Verif.verify())

    def test_different_m(self):
        for _ in range(3):
            for i in range(1, 6):
                m = 2 ** i
                seeds = [os.urandom(10) for _ in range(7)]
                vs, n = [ModP(randint(0, 2 ** 16 - 1), p) for _ in range(m)], 16
                gs = [
                    elliptic_hash(str(i).encode() + seeds[0], CURVE)
                    for i in range(n * m)
                ]
                hs = [
                    elliptic_hash(str(i).encode() + seeds[1], CURVE)
                    for i in range(n * m)
                ]
                g = elliptic_hash(seeds[2], CURVE)
                h = elliptic_hash(seeds[3], CURVE)
                u = elliptic_hash(seeds[4], CURVE)
                gammas = [mod_hash(seeds[5], p) for _ in range(m)]
                Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]
                Prov = AggregNIRangeProver(
                    vs, n, g, h, gs, hs, gammas, u, CURVE, seeds[6]
                )
                proof = Prov.prove()
                Verif = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
                with self.subTest(seeds=seeds, vs=vs, m=m):
                    self.assertTrue(Verif.verify())

    def test_prover_cheating_false_vs(self):
        m = 4
        seeds = [os.urandom(10) for _ in range(7)]
        vs, n = [ModP(randint(0, 2 ** 16 - 1), p) for _ in range(m)], 16
        ind = randint(0, len(vs) - 1)
        vs[ind] = ModP(randint(2 ** 16, 2 ** 17), p)
        gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n * m)]
        hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n * m)]
        g = elliptic_hash(seeds[2], CURVE)
        h = elliptic_hash(seeds[3], CURVE)
        u = elliptic_hash(seeds[4], CURVE)
        gammas = [mod_hash(seeds[5], p) for _ in range(m)]
        Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]
        Prov = AggregNIRangeProver(vs, n, g, h, gs, hs, gammas, u, CURVE, seeds[6])
        proof = Prov.prove()
        Verif = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
        with self.subTest(seeds=seeds, vs=vs, ind=ind):
            with self.assertRaisesRegex(Exception, "Proof invalid"):
                Verif.verify()

    def test_prover_cheating_false_commitment(self):
        m = 4
        seeds = [os.urandom(10) for _ in range(7)]
        vs, n = [ModP(randint(0, 2 ** 16 - 1), p) for _ in range(m)], 16
        gs = [elliptic_hash(str(i).encode() + seeds[0], CURVE) for i in range(n * m)]
        hs = [elliptic_hash(str(i).encode() + seeds[1], CURVE) for i in range(n * m)]
        g = elliptic_hash(seeds[2], CURVE)
        h = elliptic_hash(seeds[3], CURVE)
        u = elliptic_hash(seeds[4], CURVE)
        gammas = [mod_hash(seeds[5], p) for _ in range(m)]
        Vs = [commitment(g, h, vs[i], gammas[i]) for i in range(m)]
        ind = randint(0, len(Vs) - 1)
        Vs[ind] = commitment(g, h, vs[ind] + 1, gammas[ind])
        Prov = AggregNIRangeProver(vs, n, g, h, gs, hs, gammas, u, CURVE, seeds[6])
        proof = Prov.prove()
        Verif = AggregRangeVerifier(Vs, g, h, gs, hs, u, proof)
        with self.subTest(seeds=seeds, vs=vs, ind=ind):
            with self.assertRaisesRegex(Exception, "Proof invalid"):
                Verif.verify()

from utils import mod_hash, point_to_b64, inner_product, ModP
from inner_product_verifier import Proof1, Proof2
from commitments import vector_commitment
from elliptic_curve_hash import elliptic_hash
from ecdsa import SECP256k1
from pippenger import Pippenger, EC
import time


class Transcript:
    def __init__(self, seed=b""):
        self.digest = seed + b"&"

    def add_point(self, g):
        self.digest += point_to_b64(g)
        self.digest += b"&"

    def add_list_points(self, gs):
        for g in gs:
            self.add_point(g)

    def add_number(self, x):
        self.digest += str(x).encode()
        self.digest += b"&"


class NIProver:
    def __init__(self, g, h, u, P, c, a, b, group, fast, seed=b""):
        assert len(g) == len(h) == len(a) == len(b)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.a = a
        self.b = b
        self.group = group
        self.transcript = Transcript(seed)
        self.fast = fast

    def prove(self):
        x = mod_hash(self.transcript.digest, self.group.order)
        self.transcript.add_number(x)
        P_new = self.P + (x * self.c) * self.u
        u_new = x * self.u
        if self.fast:
            Prov2 = FastNIProver2(
                self.g,
                self.h,
                u_new,
                P_new,
                self.a,
                self.b,
                self.group,
                self.transcript.digest,
            )
        else:
            Prov2 = NIProver2(
                self.g,
                self.h,
                u_new,
                P_new,
                self.a,
                self.b,
                self.group,
                self.transcript.digest,
            )

        return Proof1(u_new, P_new, Prov2.prove(), self.transcript.digest)


class NIProver2:
    def __init__(self, g, h, u, P, a, b, group, transcript=b""):
        assert len(g) == len(h) == len(a) == len(b)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.a = a
        self.b = b
        self.group = group
        self.transcript = transcript

    def prove(self):
        if len(self.a) == len(self.b) == len(self.g) == len(self.h) == 1:
            return self.g, self.h, self.u, self.P, self.a, self.b, self.transcript
        np = len(self.a) // 2
        cl = inner_product(self.a[:np], self.b[np:])
        cr = inner_product(self.a[np:], self.b[:np])
        L = (
            vector_commitment(self.g[np:], self.h[:np], self.a[:np], self.b[np:])
            + cl * self.u
        )
        R = (
            vector_commitment(self.g[:np], self.h[np:], self.a[np:], self.b[:np])
            + cr * self.u
        )
        self.transcript += point_to_b64(L) + point_to_b64(R)
        x = mod_hash(self.transcript, self.group.order)
        self.transcript += str(x).encode()
        gp = [
            x.inv() * gi_fh + x * gi_sh
            for gi_fh, gi_sh in zip(self.g[:np], self.g[np:])
        ]
        hp = [
            x * hi_fh + x.inv() * hi_sh
            for hi_fh, hi_sh in zip(self.h[:np], self.h[np:])
        ]
        Pp = (x ** 2) * L + self.P + (x.inv() ** 2) * R
        ap = [
            x * ai_fh + x.inv() * ai_sh
            for ai_fh, ai_sh in zip(self.a[:np], self.a[np:])
        ]
        bp = [
            x.inv() * bi_fh + x * bi_sh
            for bi_fh, bi_sh in zip(self.b[:np], self.b[np:])
        ]

        return NIProver2(
            gp, hp, self.u, Pp, ap, bp, self.group, self.transcript
        ).prove()


class FastNIProver2:
    def __init__(self, g, h, u, P, a, b, group, transcript=None):
        assert len(g) == len(h) == len(a) == len(b)
        assert len(a) & (len(a) - 1) == 0
        self.log_n = len(a).bit_length() - 1
        self.n = len(a)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.a = a
        self.b = b
        self.group = group
        self.transcript = Transcript()
        if transcript:
            self.transcript.digest += transcript
            self.init_transcript_length = len(transcript.split(b"&"))

    def prove(self):
        gp = self.g
        hp = self.h
        ap = self.a
        bp = self.b

        xs = []
        Ls = []
        Rs = []

        while True:
            if len(ap) == len(bp) == len(gp) == len(hp) == 1:
                return Proof2(
                    ap[0],
                    bp[0],
                    xs,
                    Ls,
                    Rs,
                    self.transcript.digest,
                    self.init_transcript_length,
                )
            np = len(ap) // 2
            cl = inner_product(ap[:np], bp[np:])
            cr = inner_product(ap[np:], bp[:np])
            L = vector_commitment(gp[np:], hp[:np], ap[:np], bp[np:]) + cl * self.u
            R = vector_commitment(gp[:np], hp[np:], ap[np:], bp[:np]) + cr * self.u
            Ls.append(L)
            Rs.append(R)
            self.transcript.add_list_points([L, R])
            x = mod_hash(self.transcript.digest, self.group.order)
            xs.append(x)
            self.transcript.add_number(x)
            gp = [x.inv() * gi_fh + x * gi_sh for gi_fh, gi_sh in zip(gp[:np], gp[np:])]
            hp = [x * hi_fh + x.inv() * hi_sh for hi_fh, hi_sh in zip(hp[:np], hp[np:])]
            ap = [x * ai_fh + x.inv() * ai_sh for ai_fh, ai_sh in zip(ap[:np], ap[np:])]
            bp = [x.inv() * bi_fh + x * bi_sh for bi_fh, bi_sh in zip(bp[:np], bp[np:])]

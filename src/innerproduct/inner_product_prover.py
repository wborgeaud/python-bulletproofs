"""Contains classes for the prover of an inner-product argument"""

from typing import Optional

from .inner_product_verifier import Proof1, Proof2
from ..utils.commitments import vector_commitment
from ..utils.utils import inner_product
from ..utils.transcript import Transcript


class NIProver:
    """Class simulating a NI prover for the inner-product argument (Protocol 1)"""
    def __init__(self, g, h, u, P, c, a, b, group, seed=b""):
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

    def prove(self) -> Proof1:
        """
        Proves the inner-product argument following Protocol 1 in the paper
        Returns a Proof1 object.
        """
        # x = mod_hash(self.transcript.digest, self.group.order)
        x = self.transcript.get_modp(self.group.q)
        self.transcript.add_number(x)
        P_new = self.P + (x * self.c) * self.u
        u_new = x * self.u
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
        return Proof1(u_new, P_new, Prov2.prove(), self.transcript.digest)


class FastNIProver2:
    """Class simulating a NI prover for the inner-product argument (Protocol 2)"""
    def __init__(self, g, h, u, P, a, b, group, transcript: Optional[bytes]=None):
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
        else:
            self.init_transcript_length = 1


    def prove(self):
        """
        Proves the inner-product argument following Protocol 2 in the paper
        Returns a Proof2 object.
        """
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
            # x = mod_hash(self.transcript.digest, self.group.order)
            x = self.transcript.get_modp(self.group.q)
            xs.append(x)
            self.transcript.add_number(x)
            gp = [x.inv() * gi_fh + x * gi_sh for gi_fh, gi_sh in zip(gp[:np], gp[np:])]
            hp = [x * hi_fh + x.inv() * hi_sh for hi_fh, hi_sh in zip(hp[:np], hp[np:])]
            ap = [x * ai_fh + x.inv() * ai_sh for ai_fh, ai_sh in zip(ap[:np], ap[np:])]
            bp = [x.inv() * bi_fh + x * bi_sh for bi_fh, bi_sh in zip(bp[:np], bp[np:])]

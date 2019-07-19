from utils import mod_hash, point_to_bytes, inner_product, ModP
from commitments import vector_commitment
from elliptic_curve_hash import elliptic_hash
from ecdsa import SECP256k1
from pippenger import Pippenger, EC
import time

SUPERCURVE = SECP256k1

class Proof1:
    def __init__(self, u_new, P_new, proof2, transcript):
        self.u_new = u_new
        self.P_new = P_new
        self.proof2 = proof2
        self.transcript = transcript

class Verifier1:
    def __init__(self, g, h, u, P, c, proof1):
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.proof1 = proof1 
    
    def assertThat(self, expr: bool):
        if not expr:
            raise Exception('Proof invalid')
    
    def verify_transcript(self):
        n = len(self.g)
        lTranscript = self.proof1.transcript.split(b'&')
        self.assertThat(all([point_to_bytes(gi)==lTi for gi,lTi in zip(self.g, lTranscript)]))
        self.assertThat(all([point_to_bytes(hi)==lTi for hi,lTi in zip(self.h, lTranscript[n:])]))
        self.assertThat(point_to_bytes(self.u) == lTranscript[2*n])
        self.assertThat(point_to_bytes(self.P) == lTranscript[2*n+1])
        self.assertThat(str(self.c).encode() == lTranscript[2*n+2])
        self.assertThat(
            lTranscript[2*n+3] == str(mod_hash(b'&'.join(lTranscript[:2*n+3])+b'&', SUPERCURVE.order)).encode()
        )


    def verify(self):
        self.verify_transcript()

        n = len(self.g)
        lTranscript = self.proof1.transcript.split(b'&')
        x = lTranscript[2*n+3]
        x = ModP(int(x), SUPERCURVE.order)
        self.assertThat(self.proof1.P_new == self.P + (x*self.c)*self.u)
        self.assertThat(self.proof1.u_new == x*self.u)

        Verif2 = Verifier2(self.g, self.h, self.proof1.u_new, self.proof1.P_new, self.proof1.proof2)

        return Verif2.verify()


class Proof2:
    def __init__(self, a, b, xs, Ls, Rs, transcript):
        self.a = a
        self.b = b
        self.xs = xs
        self.Ls = Ls
        self.Rs = Rs
        self.transcript = transcript

class Verifier2:
    def __init__(self, g, h, u, P, proof: Proof2):
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.proof = proof

    def assertThat(self, expr):
        if not expr:
            raise Exception('Proof invalid')

    def get_ss(self, xs):
        n = len(self.g)
        log_n = n.bit_length()-1
        ss = []
        for i in range(1, n+1):
            tmp = ModP(1, SUPERCURVE.order)
            for j in range(0, log_n):
                b = 1 if bin(i-1)[2:].zfill(log_n)[j]=='1' else -1 
                tmp *= xs[j] if b==1 else xs[j].inv()
            ss.append(tmp)
        return ss
    
    def verify_transcript(self):
        n = len(self.g)
        log_n = n.bit_length()-1
        Ls = self.proof.Ls
        Rs = self.proof.Rs
        xs = self.proof.xs
        lTranscript = self.proof.transcript.digest.split(b'&')
        for i in range(log_n):
            self.assertThat(lTranscript[i*3] == point_to_bytes(Ls[i]))
            self.assertThat(lTranscript[i*3+1] == point_to_bytes(Rs[i]))
            self.assertThat(
                lTranscript[i*3+2] ==
                 str(mod_hash(b'&'.join(lTranscript[:i*3+2])+b'&', SUPERCURVE.order)).encode()
            )



    def verify(self):
        self.verify_transcript()

        proof = self.proof
        G = EC(SUPERCURVE)
        Pip = Pippenger(G)
        ss = self.get_ss(self.proof.xs)
        LHS = Pip.multiexp(
            self.g+self.h+[self.u],
            [proof.a*ssi for ssi in ss]+[proof.b*ssi.inv() for ssi in ss]+[proof.a*proof.b]
            )
        RHS = self.P + Pip.multiexp(
            proof.Ls+proof.Rs,
            [xi**2 for xi in proof.xs]+[xi.inv()**2 for xi in proof.xs]
            )
        
        self.assertThat(LHS == RHS)
        print('OK')
        return True



class NIProver:

    def __init__(self, g, h, u, P, c, a, b, group, fast):
        assert len(g) == len(h) == len(a) == len(b)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.a = a
        self.b = b
        self.group = group
        self.transcript = b''
        self.fast = fast 
    
    def prove(self):
        self.transcript += (
            b''.join([point_to_bytes(gi) for gi in self.g]) +
            b''.join([point_to_bytes(hi) for hi in self.h]) +
            point_to_bytes(self.u) +
            point_to_bytes(self.P) +
            str(self.c).encode()
        )
        x = mod_hash(self.transcript, self.group.order)
        self.transcript += str(x).encode()
        P_new = self.P + (x*self.c) * u
        if self.fast:
            Prov2 = FastNIProver2(self.g, self.h, x*self.u, P_new, self.a, self.b, self.group, self.transcript)
        else:
            Prov2 = NIProver2(self.g, self.h, x*self.u, P_new, self.a, self.b, self.group, self.transcript)

        return Prov2.prove()

class NIProver2:

    def __init__(self, g, h, u, P, a, b, group, transcript=b''):
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
        cl = inner_product(self.a[:np],self.b[np:])
        cr = inner_product(self.a[np:],self.b[:np])
        L = vector_commitment(self.g[np:],self.h[:np],self.a[:np],self.b[np:]) + cl*self.u
        R = vector_commitment(self.g[:np],self.h[np:],self.a[np:],self.b[:np]) + cr*self.u
        self.transcript += (point_to_bytes(L) + point_to_bytes(R))
        x = mod_hash(self.transcript, self.group.order)
        self.transcript += str(x).encode()
        gp = [x.inv()*gi_fh + x*gi_sh for gi_fh,gi_sh in zip(self.g[:np],self.g[np:])]
        hp = [x*hi_fh + x.inv()*hi_sh for hi_fh,hi_sh in zip(self.h[:np],self.h[np:])]
        Pp = (x**2)*L + self.P + (x.inv()**2)*R
        ap = [x*ai_fh + x.inv()*ai_sh for ai_fh,ai_sh in zip(self.a[:np],self.a[np:])]
        bp = [x.inv()*bi_fh + x*bi_sh for bi_fh,bi_sh in zip(self.b[:np],self.b[np:])]

        return NIProver2(gp, hp, self.u, Pp, ap, bp, self.group, self.transcript).prove()

class FastNIProver2:

    def __init__(self, g, h, u, P, a, b, group, transcript=b''):
        assert len(g) == len(h) == len(a) == len(b)
        assert len(a)&(len(a)-1) == 0
        self.log_n = len(a).bit_length()-1
        self.n = len(a)
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.a = a
        self.b = b
        self.group = group
        self.transcript = transcript
    
    def get_ss(self, xs):
        ss = []
        for i in range(1, self.n+1):
            tmp = ModP(1, self.group.order)
            for j in range(0, self.log_n):
                b = 1 if bin(i-1)[2:].zfill(self.log_n)[j]=='1' else -1 
                tmp *= xs[j] if b==1 else xs[j].inv()
            ss.append(tmp)
        return ss

    
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
                ss = self.get_ss(xs)
                return self.u, self.P, ap, bp, xs, ss, Ls, Rs, self.transcript
            np = len(ap) // 2
            cl = inner_product(ap[:np],bp[np:])
            cr = inner_product(ap[np:],bp[:np])
            L = vector_commitment(gp[np:],hp[:np],ap[:np],bp[np:]) + cl*self.u
            R = vector_commitment(gp[:np],hp[np:],ap[np:],bp[:np]) + cr*self.u
            Ls.append(L)
            Rs.append(R)
            self.transcript += (point_to_bytes(L) + point_to_bytes(R))
            x = mod_hash(self.transcript, self.group.order)
            xs.append(x)
            self.transcript += str(x).encode()
            gp = [x.inv()*gi_fh + x*gi_sh for gi_fh,gi_sh in zip(gp[:np],gp[np:])]
            hp = [x*hi_fh + x.inv()*hi_sh for hi_fh,hi_sh in zip(hp[:np],hp[np:])]
            ap = [x*ai_fh + x.inv()*ai_sh for ai_fh,ai_sh in zip(ap[:np],ap[np:])]
            bp = [x.inv()*bi_fh + x*bi_sh for bi_fh,bi_sh in zip(bp[:np],bp[np:])]

def verify(g,h,u,P,a,b):
    c = a*b
    if P == a*g + b*h + c*u:
        print('OK')
    else:
        print('Not OK')
    return P, a*g + b*h + c*u

def fast_verify(g, h, u, P, a, b, xs, ss, Ls, Rs, transcript):
    G = EC(SUPERCURVE)
    Pip = Pippenger(G)
    LHS = Pip.multiexp(g+h+[u],[a*ssi for ssi in ss]+[b*ssi.inv() for ssi in ss]+[a*b])
    RHS = P + Pip.multiexp(Ls+Rs, [xi**2 for xi in xs]+[xi.inv()**2 for xi in xs])
    
    if LHS == RHS:
        print('OK')
    else:
        print('Not OK')


# SUPERCURVE = SECP256k1
# CURVE = SUPERCURVE.curve
# p = SUPERCURVE.order

# N = 256

# g = [elliptic_hash(str(i).encode() + b'This', CURVE) for i in range(N)]
# h = [elliptic_hash(str(i).encode() + b'is', CURVE) for i in range(N)]
# u = elliptic_hash(b'a test', CURVE)

# a = [mod_hash(str(i).encode() + b'testing', p) for i in range(N)]
# b = [mod_hash(str(i).encode() + b'still testing', p) for i in range(N)]

# P = vector_commitment(g,h,a,b)
# c = inner_product(a,b)

# start = time.time()
# Prov = NIProver(g,h,u,P,c,a,b,SECP256k1,False)
# pg, ph, pu, pP, pa, pb, pTranscript = Prov.prove()
# print(time.time()-start)
# tLHS, tRHS = verify(pg[0],ph[0],pu,pP,pa[0],pb[0])
# print(time.time()-start)

# start = time.time()
# Prov = NIProver(g,h,u,P,c,a,b,SECP256k1,True)
# pu, pP, pa, pb, pxs, pss, pLs, pRs, pTranscript = Prov.prove()
# print(time.time()-start)
# fast_verify(g,h,pu,pP,pa[0],pb[0],pxs,pss,pLs,pRs,pTranscript)
# print(time.time()-start)

# # print(pTranscript)
# # print(len(pTranscript))
# # print(len(hex(int(pTranscript))))
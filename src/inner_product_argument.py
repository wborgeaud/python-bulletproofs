from utils import mod_hash, point_to_bytes, inner_product, ModP
from commitments import vector_commitment
from elliptic_curve_hash import elliptic_hash
from ecdsa import SECP256k1

class Verifier:

    def __init__(self, g, h, P, c):
        self.g = g
        self.h = h
        self.u = u
        self.P = P
        self.c = c
        self.a = a
        self.b = b


class NIProver:

    def __init__(self, g, h, u, P, c, a, b, group):
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
        Prov2 = FastNIProver2(self.g, self.h, x*self.u, P_new, self.a, self.b, self.group, self.transcript)
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
            for j in range(1, self.log_n+1):
                b = 1 if bin(i-1)[2:].zfill(self.log_n+1)[-j]=='1' else -1 
                tmp *= xs[j-1] if b==1 else xs[j-1].inv()
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
                return self.g, self.h, self.u, self.P, ap, bp, xs, ss, Ls, Rs, self.transcript
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

CURVE = SECP256k1.curve
p = SECP256k1.order

N = 16

g = [elliptic_hash(str(i).encode() + b'This', CURVE) for i in range(N)]
h = [elliptic_hash(str(i).encode() + b'is', CURVE) for i in range(N)]
u = elliptic_hash(b'a test', CURVE)

a = [mod_hash(str(i).encode() + b'testing', p) for i in range(N)]
b = [mod_hash(str(i).encode() + b'still testing', p) for i in range(N)]

P = vector_commitment(g,h,a,b)
c = inner_product(a,b)
# self.g, self.h, self.u, self.P, ap, bp, xs, ss, Ls, Rs self.transcript

Prov = NIProver(g,h,u,P,c,a,b,SECP256k1)
pg, ph, pu, pP, pa, pb, pTranscript = Prov.prove()

verify(pg[0],ph[0],pu,pP,pa[0],pb[0])
print(pTranscript)
print(len(pTranscript))
print(len(hex(int(pTranscript))))
from hashlib import sha256
from ecdsa.ellipticcurve import Point

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

class ModP:
    def __init__(self, x, p):
        self.x = x
        self.p = p

    def __add__(self, y):
        if isinstance(y, int):
            return ModP(self.x+y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __mul__(self, y):
        if isinstance(y, int):
            return ModP(self.x*y, self.p)
        if isinstance(y, Point):
            return self.x * y
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP(self.x-y, self.p)
        assert self.p == y.p
        return ModP((self.x - y.x) % self.p, self.p)
    
    def __pow__(self, n):
        return ModP(pow(self.x, n, self.p), self.p)

    def __mod__(self, other):
        return self.x % other
    
    def __neg__(self):
        return ModP(self.p - self.x, self.p)
    
    def inv(self):
        g, a, b = egcd(self.x, self.p)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return ModP(a % self.p, self.p)

    def __str__(self):
        return str(self.x)
    def __repr__(self):
        return str(self.x)

def mod_hash(msg, p, non_zero=True):
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h,16)
        if x >= p:
            continue
        elif non_zero and x==0:
            continue
        else:
            return ModP(x,p)

def point_to_bytes(g):
    return (str(g.x()) + str(g.y())).encode()

def inner_product(a, b):
    assert len(a) == len(b)
    return sum([ai*bi for ai,bi in zip(a,b)], ModP(0, a[0].p))
from hashlib import sha256
from ecdsa.ellipticcurve import Point
from ecdsa import SECP256k1
from ecdsa.numbertheory import square_root_mod_prime
import base64

SUPERCURVE = SECP256k1
BYTE_LENGTH = SUPERCURVE.order.bit_length() // 8


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
            return ModP(self.x + y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __mul__(self, y):
        if isinstance(y, int):
            return ModP(self.x * y, self.p)
        if isinstance(y, Point):
            return self.x * y
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP(self.x - y, self.p)
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
            raise Exception("modular inverse does not exist")
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
        x = int(h, 16)
        if x >= p:
            continue
        elif non_zero and x == 0:
            continue
        else:
            return ModP(x, p)


def point_to_bytes(g):
    if g == Point(None, None, None):
        return b"\x00"
    x_enc = g.x().to_bytes(BYTE_LENGTH, "big")
    prefix = b"\x03" if g.y() % 2 else b"\x02"
    return prefix + x_enc
    # return (str(g.x()) + str(g.y())).encode()


def point_to_b64(g):
    return base64.b64encode(point_to_bytes(g))


def b64_to_point(s):
    return bytes_to_point(base64.b64decode(s))


def bytes_to_point(b):
    p = SUPERCURVE.curve.p()
    yp, x_enc = b[0], b[1:]
    yp = 0 if yp==2 else 1
    x = int.from_bytes(x_enc, "big")
    y = square_root_mod_prime(
        (x ** 3 + SUPERCURVE.curve.a() * x + SUPERCURVE.curve.b())%p, p
    )
    if y%2 == yp:
        return Point(SUPERCURVE.curve, x, y)
    else:
        return Point(SUPERCURVE.curve, x, p-y)


def inner_product(a, b):
    assert len(a) == len(b)
    return sum([ai * bi for ai, bi in zip(a, b)], ModP(0, a[0].p))


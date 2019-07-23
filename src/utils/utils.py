"""Contains various utilities"""

from hashlib import sha256
from typing import List
import base64

from fastecdsa.point import Point
from fastecdsa.curve import secp256k1
from fastecdsa.util import mod_sqrt

CURVE = secp256k1
BYTE_LENGTH = CURVE.q.bit_length() // 8


def egcd(a, b):
    """Extended euclid algorithm"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


class ModP:
    """Class representing an integer mod p"""

    def __init__(self, x, p):
        self.x = x
        self.p = p

    def __add__(self, y):
        if isinstance(y, int):
            return ModP(self.x + y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __radd__(self, y):
        return self + y

    def __mul__(self, y):
        if isinstance(y, int):
            return ModP(self.x * y, self.p)
        if isinstance(y, Point):
            return self.x * y
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP((self.x - y) % self.p, self.p)
        assert self.p == y.p
        return ModP((self.x - y.x) % self.p, self.p)

    def __rsub__(self, y):
        return -(self - y)

    def __pow__(self, n):
        return ModP(pow(self.x, n, self.p), self.p)

    def __mod__(self, other):
        return self.x % other

    def __neg__(self):
        return ModP(self.p - self.x, self.p)

    def inv(self):
        """Returns the modular inverse"""
        g, a, _ = egcd(self.x, self.p)
        if g != 1:
            raise Exception("modular inverse does not exist")
        else:
            return ModP(a % self.p, self.p)

    def __eq__(self, y):
        return (self.p == y.p) and (self.x % self.p == y.x % self.p)

    def __str__(self):
        return str(self.x)

    def __repr__(self):
        return str(self.x)


def mod_hash(msg: bytes, p: int, non_zero: bool = True) -> ModP:
    """Takes a message and a prime and returns a hash in ModP"""
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16) % 2 ** p.bit_length()
        if x >= p:
            continue
        elif non_zero and x == 0:
            continue
        else:
            return ModP(x, p)


def point_to_bytes(g: Point) -> bytes:
    """Takes an EC point and returns the compressed bytes representation"""
    if g == Point.IDENTITY_ELEMENT:
        return b"\x00"
    x_enc = g.x.to_bytes(BYTE_LENGTH, "big")
    prefix = b"\x03" if g.y % 2 else b"\x02"
    return prefix + x_enc


def point_to_b64(g: Point) -> bytes:
    """Takes an EC point and returns the base64 compressed bytes representation"""
    return base64.b64encode(point_to_bytes(g))


def b64_to_point(s: bytes) -> Point:
    """Takes a base64 compressed bytes representation and returns the corresponding point"""
    return bytes_to_point(base64.b64decode(s))


def bytes_to_point(b: bytes) -> Point:
    """Takes a compressed bytes representation and returns the corresponding point"""
    if b == 0:
        return Point.IDENTITY_ELEMENT
    p = CURVE.p
    yp, x_enc = b[0], b[1:]
    yp = 0 if yp == 2 else 1
    x = int.from_bytes(x_enc, "big")
    y = mod_sqrt((x ** 3 + CURVE.a * x + CURVE.b) % p, p)
    if y % 2 == yp:
        return Point(x, y, CURVE)
    else:
        return Point(x, p - y, CURVE)


def inner_product(a: List[ModP], b: List[ModP]) -> ModP:
    """Inner-product of vectors in Z_p"""
    assert len(a) == len(b)
    return sum([ai * bi for ai, bi in zip(a, b)], ModP(0, a[0].p))

from fastecdsa.point import Point
from fastecdsa.curve import Curve
from ecdsa.numbertheory import square_root_mod_prime, SquareRootError
from hashlib import sha256, md5


def elliptic_hash(msg: bytes, CURVE: Curve):
    p = CURVE.p
    i = 0
    while True:
        i += 1
        prefixed_msg = str(i).encode() + msg
        h = sha256(prefixed_msg).hexdigest()
        x = int(h, 16)
        if x >= p:
            continue

        y_sq = (x ** 3 + CURVE.a * x + CURVE.b) % p
        try:
            y = square_root_mod_prime(y_sq, p)
        except SquareRootError:
            continue

        b = int(md5(prefixed_msg).hexdigest(), 16) % 2
        return Point(x, y, CURVE) if b else Point(x, p - y, CURVE)


from fastecdsa.point import Point
from fastecdsa.curve import Curve
from fastecdsa.util import mod_sqrt
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
        y = mod_sqrt(y_sq, p)[0]

        if CURVE.is_point_on_curve((x, y)):
            b = int(md5(prefixed_msg).hexdigest(), 16) % 2
            return Point(x, y, CURVE) if b else Point(x, p - y, CURVE)


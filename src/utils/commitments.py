from fastecdsa.point import Point
from ..pippenger import PipSECP256k1


def commitment(g, h, x, r):
    return x * g + r * h


def vector_commitment(g, h, a, b):
    assert len(g) == len(h) == len(a) == len(b)
    # return sum([ai*gi for ai,gi in zip(a,g)], Point(None,None,None)) \
    #         + sum([bi*hi for bi,hi in zip(b,h)], Point(None,None,None))
    return PipSECP256k1.multiexp(g + h, a + b)


def _mult(a: int, g: Point) -> Point:
    if a < 0 and abs(a) < 2 ** 32:
        return abs(a) * _inv(g)
    else:
        return a * g


def _inv(g: Point) -> Point:
    return Point(g.x, -g.y, g.curve)

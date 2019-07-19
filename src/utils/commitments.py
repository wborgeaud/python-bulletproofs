from ecdsa.ellipticcurve import Point

def commitment(g, h, x, r):
    return x*g + r*h

def vector_commitment(g, h, a, b):
    assert len(g) == len(h) == len(a) == len(b)
    return sum([ai*gi for ai,gi in zip(a,g)], Point(None,None,None)) \
             + sum([bi*hi for bi,hi in zip(b,h)], Point(None,None,None)) 
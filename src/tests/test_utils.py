import unittest
import os
from random import randint
from fastecdsa.curve import secp256k1

from ..utils.utils import (
    mod_hash,
    bytes_to_point,
    point_to_bytes,
    b64_to_point,
    point_to_b64,
)
from ..utils.elliptic_curve_hash import elliptic_hash

CURVE = secp256k1


class HashTest(unittest.TestCase):
    def test_mod_hash(self):
        p = 1009
        x = mod_hash(b"test", p)
        self.assertLess(x.x, p)
        self.assertEqual(x, mod_hash(b"test", p))
        p = 17
        for _ in range(100):
            msg = os.urandom(10)
            x = mod_hash(msg, p)
            with self.subTest(msg=msg, p=p):
                self.assertNotEqual(x.x, 0)

    def test_elliptic_hash(self):
        for _ in range(100):
            msg = os.urandom(10)
            x = elliptic_hash(msg, CURVE)
            with self.subTest(msg=msg):
                self.assertTrue(CURVE.is_point_on_curve((x.x, x.y)))


class ConversionTest(unittest.TestCase):
    def test_point_to_bytes(self):
        for _ in range(100):
            e = randint(0, CURVE.q)
            x = e * CURVE.G
            with self.subTest(e=e):
                self.assertEqual(bytes_to_point(point_to_bytes(x)), x)

    def test_point_to_b64(self):
        for _ in range(100):
            e = randint(0, CURVE.q)
            x = e * CURVE.G
            with self.subTest(e=e):
                self.assertEqual(b64_to_point(point_to_b64(x)), x)


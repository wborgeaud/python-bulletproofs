from fastecdsa.curve import secp256k1
from .pippenger import Pippenger
from .group import EC

PipSECP256k1 = Pippenger(EC(secp256k1))

__all__ = ["Pippenger", "EC", "PipSECP256k1"]
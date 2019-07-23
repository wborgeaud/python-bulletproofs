from abc import ABC, abstractmethod
from .modp import ModP
from fastecdsa.curve import Curve


class Group(ABC):
    def __init__(self, unit, order):
        self.unit = unit
        self.order = order

    @abstractmethod
    def mult(self, x, y):
        pass

    def square(self, x):
        return self.mult(x, x)


class MultIntModP(Group):
    def __init__(self, p, order):
        Group.__init__(self, ModP(1, p), order)

    def mult(self, x, y):
        return x * y


class EC(Group):
    def __init__(self, curve: Curve):
        Group.__init__(self, curve.G.IDENTITY_ELEMENT, curve.q)

    def mult(self, x, y):
        return x + y

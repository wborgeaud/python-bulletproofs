from abc import ABC, abstractmethod
from .modp import ModP
from ecdsa.ellipticcurve import Point

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
        return x*y

class EC(Group):
    def __init__(self, curve):
        Group.__init__(self, Point(None,None,None),  curve.order)
    
    def mult(self, x, y):
        return x + y
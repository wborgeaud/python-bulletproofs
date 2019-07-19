class ModP:

    num_of_mult=0
    @classmethod
    def reset(cls):
        cls.num_of_mult = 0

    def __init__(self, x, p):
        self.x = x
        self.p = p

    def __add__(self, y):
        if isinstance(y, int):
            return ModP(self.x+y, self.p)
        assert self.p == y.p
        return ModP((self.x + y.x) % self.p, self.p)

    def __mul__(self, y):
        type(self).num_of_mult += 1
        if isinstance(y, int):
            return ModP(self.x*y, self.p)
        assert self.p == y.p
        return ModP((self.x * y.x) % self.p, self.p)

    def __sub__(self, y):
        if isinstance(y, int):
            return ModP(self.x-y, self.p)
        assert self.p == y.p
        return ModP((self.x - y.x) % self.p, self.p)
    
    def __pow__(self, n):
        # return ModP(pow(self.x, n, self.p), self.p)
        exp = bin(n)
        value = ModP(self.x, self.p)
    
        for i in range(3, len(exp)):
            value = value * value
            if(exp[i:i+1]=='1'):
                value = value*self
        return value
    
    
    def __neg__(self):
        return ModP(self.p - self.x, self.p)
    
    def __eq__(self, y):
        return (self.x == y.x) and (self.p == y.p)

    
    def __str__(self):
        return str(self.x)
    def __repr__(self):
        return str(self.x)
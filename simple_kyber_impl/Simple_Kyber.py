import random
from sympy import Poly
from sympy.abc import x, y
from sympy import GF
from random import SystemRandom
from Utils import bytearray_to_bitarray
cryptogen = SystemRandom()
import numpy as np
import decimal

# Rounding function, rounds up on tie
decimal.getcontext().rounding = decimal.ROUND_HALF_UP
def round(number):
    return int(decimal.Decimal(number).to_integral_value())

# Global definitions
q = 3329
n = 256
dom = GF(q, symmetric=False)
f = Poly(1 + x**n, domain=dom)
zero = Poly(0, x, domain=dom)
two_squared = [1, 2, 4, 8, 16, 32, 64, 128]

class Simple_Kyber:
    def __init__(self, k: int):
        self.k = k
        self.key_generation()

    def key_generation(self):
        self.s = np.array([[self.generate_poly(-1, 3)] for _ in range(self.k)])
        self.A = np.array([[self.generate_poly() for _ in range(self.k)] for _ in range(self.k)])
        self.e = np.array([[self.generate_poly(-1, 3)] for _ in range(self.k)])
        self.t = self.poly_add(self.poly_mul(self.A, self.s), self.e)

    def encrypt(self, m: bytes):
        if len(m) != 32:
            raise ValueError('Message must have length of 32 bytes, 256 bits')
        # Transform message into polynomial
        message = np.array(bytearray_to_bitarray(m))
        message = message * round(q/2)
        message = Poly(message, x)

        # Generate Encryption spec freshly
        r = np.array([[self.generate_poly(-1, 3)] for _ in range(self.k)])
        e_one = np.array([[self.generate_poly(-1, 3)] for _ in range(self.k)])
        e_two = self.generate_poly(-1, 3)

        # Calculate u,v
        u = self.poly_add(self.poly_mul(r.transpose(), self.A), e_one.transpose()).transpose()
        v = np.array([[Poly(self.poly_mul(r.transpose(), self.t)[0][0] + e_two + message, domain=dom)]])
        return (u, v)

    def decrypt(self, c: tuple):
        (u, v) = c
        m = self.poly_sub(v, self.poly_mul(self.s.transpose(), u))[0][0]
        m = m.all_coeffs()

        # Highest order coeffs might have been 0 and all_coeffs doesn't return them
        while len(m) < 256:
            m.insert(0, 0)

        # Recover message from coeffs
        m_recovered = [0] * 32
        q_1 = round(q*0.25)
        q_2 = round(q*0.75)
        for i in range(32):
            for j in range(8):
                if q_1 < m[i*8 + j] <= q_2:
                    m_recovered[i] += two_squared[j]
        return bytes(m_recovered)

    def generate_poly(self, offset: int = 0, range_dis: int = q):
        """
        - cryptogen.randrange(range) returns number in [0, range-1]
        - Poly gets an array of n coefficients with x as a generator
        - offset: shift range by offset, e.g. [0, 2] -> -1 -> [-1, 1]
        - range_dis: range from which to choose random value -> [0, range_dis - 1]
        """
        return Poly([cryptogen.randrange(range_dis) + offset for _ in range(n)], x)

    def poly_mul(self, x, y):
        rows = x.shape[0]
        cols = y.shape[1]
        y_rows = y.shape[0]
        result = np.full((rows, cols), zero)  # Array mit 0 initialisieren
        for i in range(rows):
            for j in range(cols):
                for k in range(y_rows):
                    result[i][j] = result[i][j].add((x[i][k].mul(y[k][j])))  # Skalarprodukt
                result[i][j] = result[i][j].rem(f)  # Modulo Polynom F
                result[i][j] = Poly(result[i][j], domain=dom)  # Modulo Primzahl Q
        return result

    def poly_add(self, x, y):
        rows = x.shape[0]
        cols = y.shape[1]
        result = np.empty((rows, cols), Poly)
        for i in range(rows):
            for j in range(cols):
                result[i][j] = Poly(x[i][j].add(y[i][j]), domain=dom)  # Modulo Primzahl Q
        return result

    def poly_sub(self, x, y):
        rows = x.shape[0]
        cols = y.shape[1]
        result = np.empty((rows, cols), Poly)
        for i in range(rows):
            for j in range(cols):
                result[i][j] = Poly(x[i][j].sub(y[i][j]), domain=dom)  # Modulo Primzahl Q
        return result


# Simple test with freshly generated KeyPairs, Encryption parameters and alternating k
m = bytes('This message is 32 bytes long!!!', 'utf-8')
for _ in range(100):
    kyber = Simple_Kyber(random.randint(2, 4))
    c = kyber.encrypt(m)
    m_rec = kyber.decrypt(c)
    print(m_rec == m)


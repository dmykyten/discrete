from random import choice
from itertools import count
from math import sqrt

class RSAKeyGen:
    _RANGE = 1000
    _primes = []

    def __init__(self):
        self.public = None
        self.private = None
        self._generate_keys()

    def _generate_keys(self):
        #p, q = self._randprime(), self._randprime()
        p, q = 53, 67
        n = p * q      # public part 1
        tmp = (p - 1) * (q - 1)

        # get e value
        e = 0
        for i in count(start=n // 2):
            if self._gcd(i, tmp) == 1 and i % 2 != 0:
                e = i
                break
        e = 17

        # doesnt work properly
        # euclid here
        #self.private = e**-1 % tmp

        self.public = n, e
        print(n, e, self.private)

    def _randprime(self):           # grabs random prime below range
        assert self._RANGE > 2

        def generate_primes():
            valid = True
            for num in range(2, self._RANGE):
                prime_sqrt = round(sqrt(num))
                for prime in self._primes:
                    if num % prime == 0:
                        valid = False
                        break
                    if prime > prime_sqrt:
                        break
                if valid:
                    self._primes.append(num)
                valid = True

        if len(self._primes) == 0:
            generate_primes()
        return choice(self._primes)

    @staticmethod
    def _gcd(num1, num2):            # from EverythingCrypto link
        if num2 == 0:
            return num1
        else:
            return RSAKeyGen._gcd(num2, num1 % num2)

from random import choice
from itertools import count
from math import sqrt
from string import ascii_letters

class RSAKeyGen:
    _RANGE = 1000
    _primes = []

    def __init__(self):
        self.public = None
        self.private = None
        self._generate_keys()

    def _generate_keys(self):
        p, q = self._randprime(), self._randprime()
        n = p * q      # public part 1
        tmp = (p - 1) * (q - 1)

        # get e value
        e = 0
        for i in count(start=n // 2):
            if self._gcd(i, tmp) == 1 and i % 2 != 0:
                e = i
                break

        self.private = pow(e, -1, tmp)

        self.public = n, e
        print(n, e, self.private)

    def _randprime(self):           # grabs random prime below range
        assert self._RANGE > 2

        def generate_primes():
            valid = True
            for num in range(100, self._RANGE):
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

    @staticmethod
    def encrypt_msg(public_key, msg):
        encrypted = ''
        # encode msg in ciphertext
        for letter in msg:
            letter_code = str(ascii_letters.find(letter))
            if letter.isupper():
                letter_code -= 25
            if int(letter_code) < 10:
                letter_code = '0' + letter_code
            encrypted += letter_code
        # find size of block 2N < public_key.n
        block_size = next((i - 1) * 2 for i in count(start=1)
                          if int('25' * i) > public_key[0])
        # convert string to list of blocks
        encrypted = [encrypted[i:i + block_size]
                     for i in range(0, len(encrypted), block_size)]
        # add fake symbols if necessary
        if len(encrypted[-1]) < block_size * 2:
            encrypted[-1] += '9' * (block_size - len(encrypted[-1]))
        print(encrypted)
        # encode message with public key
        encrypted = [pow(int(block), public_key[1], public_key[0])
                     for block in encrypted]
        return encrypted

    @staticmethod
    def decrypt_msg(private_key, msg):
        pass

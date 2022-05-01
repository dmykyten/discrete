from random import choice
from itertools import count
from hashlib import sha256, sha3_512
from secrets import compare_digest


class RSAKeyGen:
    _RANGE = 5000
    _primes = []

    def __init__(self):
        self.public = None
        self.private = None
        self._generate_keys()

    def _generate_keys(self):
        p, q = self._randprime(), self._randprime()
        n = p * q  # public part 1
        tmp = (p - 1) * (q - 1)

        # get e value
        e = 0
        for i in count(start=n // 2):
            if self._gcd(i, tmp) == 1 and i % 2 != 0:
                e = i
                break

        d = pow(e, -1, tmp)
        self.private = n, d
        self.public = n, e

        # print(f"public: {self.public}\nprivate:{self.private}")

    def _randprime(self):  # grabs random prime below range
        assert self._RANGE > 2

        def generate_primes():
            for num in range(1000, self._RANGE):
                for prime in range(2, num):
                    if num % prime == 0:
                        break
                else:
                    self._primes.append(num)

        if len(self._primes) == 0:
            generate_primes()
        return choice(self._primes)

    @staticmethod
    def _gcd(num1, num2):  # from EverythingCrypto link
        if num2 == 0:
            return num1
        else:
            return RSAKeyGen._gcd(num2, num1 % num2)

    @staticmethod
    def encrypt_msg(public_key, msg):
        # set constant for convenience
        BLOCK_SIZE = 6
        encrypted = ""
        # encode msg in ciphertext
        for letter in msg:
            letter_code = str(ord(letter))
            if int(letter_code) < 100:
                letter_code = "0" + letter_code
            encrypted += letter_code
        # convert string to list of blocks
        encrypted = [
            encrypted[i: i + BLOCK_SIZE] for i in range(0, len(encrypted), BLOCK_SIZE)
        ]
        # encode message with public key
        # C = M^e mod n
        encrypted = [
            pow(int(block), public_key[1], public_key[0]) for block in encrypted
        ]

        return encrypted

    @staticmethod
    def decrypt_msg(private_key, msg):
        # decode encrypted message
        # M = C^d mod n
        msg = [pow(block, private_key[1], private_key[0]) for block in msg]
        decrypted = []
        for i, block in enumerate(msg):
            # if msg is too short, write zeros
            if len(str(block)) != 6 or len(str(block)) != 3:
                block = (
                    str(block).zfill(6)
                    if len(str(block)) == 5
                    else str(block).zfill(3)
                )
            msg[i] = str(block)
            # divide all items in msg into blocks of 3
            decrypted.extend(
                [block[:3], block[3:]] if len(block) == 6 else [block[:3]]
            )
        # decode ascii codes to get message as string
        decrypted = "".join([chr(int(i)) for i in decrypted])
        return decrypted


def get_hash(msg):
    hashed_data = (sha3_512(msg.encode("utf-8"))).digest()
    return hashed_data


def verify_integrity(expected_hash, msg):
    actual_hash = get_hash(msg)
    return compare_digest(expected_hash, actual_hash)

def check_hash(msg_hash, msg):
    try:
        if not verify_integrity(msg_hash, msg):
            raise Exception("Invalid hash. Connection is insecure")
        print("Valid hash. Connection secure")
        return True
    except Exception as e:
        print(e)
        return False


def _tests():
    srv = RSAKeyGen()
    data = "Hello, my name "
    hashed_data = get_hash(data)
    print("data is: " + f"'{data}'")
    #print("hashed is: " + str(hashed_data))
    decrypted_message = srv.decrypt_msg(
        srv.private, srv.encrypt_msg(srv.public, data)
    )
    print(decrypted_message)
    print(verify_integrity(hashed_data, decrypted_message))


if __name__ == '__main__':
    _tests()

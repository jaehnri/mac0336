import secrets
import hashlib
from math import gcd

def generate_random_128_bit():
    return format(secrets.randbits(128), '0128b')

def complement_to_n_bits(sequence, n):
    return sequence.ljust(n, '0')

def G(r):
    hash_object = hashlib.sha3_256(r.encode())
    hashed_sequence = hash_object.hexdigest()

    int_from_hex = int(hashed_sequence, 16)
    result = format(int_from_hex, '0256b')

    return result[:128]

def xor_128_bit_sequences(a, b):
    int_a = int(a, 2)
    int_b = int(b, 2)

    result = int_a ^ int_b
    
    return format(result, '0128b')

def oaep_padding(nusp):
    r = generate_random_128_bit()
    complemented_r = complement_to_n_bits(r, 256)

    message = "{:032b}".format(nusp)
    complemented_message = complement_to_n_bits(message, 128)

    gr = G(complemented_r)

    x = xor_128_bit_sequences(gr, complemented_message)
    complemented_x = complement_to_n_bits(x, 256)

    hx = G(complemented_x)
    y = xor_128_bit_sequences(hx, r)

    return x, y

def oaep_unpadding(x, y):
    complemented_x = complement_to_n_bits(x, 256)
    r = xor_128_bit_sequences(G(complemented_x), y)

    complemented_r = complement_to_n_bits(r, 256)
    complemented_message = xor_128_bit_sequences(x, G(complemented_r))
    message = complemented_message[:32]

    return message


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

class RSA:
    def __init__(self, q, r):
        self.q = q
        self.r = r
        self.n = q * r
        self.phi = (q - 1) * (r - 1)
        self.public_key, self.private_key = self.generate_key_pair()

    def generate_key_pair(self):
        # Find s such that s and phi(n) are coprime
        s = secrets.randbelow(self.phi)
        while gcd(s, self.phi) != 1:
            s = secrets.randbelow(self.phi)
        
        p = mod_inverse(s, self.phi)
        return p, s

    def encrypt(self, message):
        return pow(message, self.public_key, self.n)

    def decrypt(self, encrypted_message):
        return pow(encrypted_message, self.private_key, self.n)

rsa = RSA(2, 11)
encrypted = rsa.encrypt(9)
print(encrypted)

decrypted = rsa.decrypt(encrypted)
print(decrypted)

x, y = oaep_padding(11796378)
print(oaep_unpadding(x, y))
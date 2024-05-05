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


def oaep(nusp):
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

def generate_keys():
    return 11, 13

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def rsa_key_pair(q, r):
    n = q * r
    phi = (q - 1) * (r - 1)
    
    # Find s such that s and phi(n) are coprime
    # s = secrets.randbelow(phi)
    s = 3
    while gcd(s, phi) != 1:
        s = secrets.randbelow(phi)
    
    p = mod_inverse(s, phi)
    public_key = (p, n)
    private_key = (s, n)

    return public_key, private_key

def rsa_encrypt(message, public_key, n):
    return pow(message, public_key, n)

def rsa_decrypt(encrypted_message, secret_key, n):
    return pow(encrypted_message, secret_key, n)


public_key, private_key = rsa_key_pair(2, 11)
print(public_key)
print(private_key)
print(rsa_encrypt(9, public_key[0], public_key[1]))
print(rsa_decrypt(15, private_key[0], private_key[1]))

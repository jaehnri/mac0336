import secrets
import hashlib

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

x, y = oaep(11796378)
print(x)
print(y)

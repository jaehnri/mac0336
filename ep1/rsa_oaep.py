import secrets
import hashlib
from math import gcd

def generate_random_128_bit():
    """
    Generates a random 128-bit binary string.
    """
    return format(secrets.randbits(128), '0128b')

def complement_to_n_bits(sequence, n):
    """
    Complements a given bit sequence with zeros to the right 
    to ensure it has a total length of `n` bits.
    """
    return sequence.ljust(n, '0')

def G(r):
    """
    Applies SHA3_256 to the input string 'r' and returns the leftmost 128 bits of the resulting hash.
    """
    hash_object = hashlib.sha3_256(r.encode())
    hashed_sequence = hash_object.hexdigest()

    int_from_hex = int(hashed_sequence, 16)
    result = format(int_from_hex, '0256b')

    return result[:128]

def xor_128_bit_sequences(a, b):
    """
    Performs bitwise XOR operation between two 128-bit binary sequences.
    """
    int_a = int(a, 2)
    int_b = int(b, 2)

    result = int_a ^ int_b
    
    return format(result, '0128b')

def mod_inverse(a, m):
    """
    Computes the modular multiplicative inverse of 'a' modulo 'm'.
    This function implements the Extended Euclidean Algorithm to find the modular inverse.

    It iteratively computes the greatest common divisor (GCD) of 'a' and 'm' and 
    simultaneously calculates the coefficients of Bezout's identity, which provides 
    the modular inverse.
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    # Ensure the result is positive within the range [0, m-1]
    return x1 + m0 if x1 < 0 else x1

def miller_rabin(n, k=40):
    # Base cases for small primes
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Write n as 2^r*c + 1
    r, c = 0, n - 1
    while c % 2 == 0:
        r += 1
        c //= 2

    for _ in range(k):
        # Choose a random integer 'a' in the range [2, n-2] = [0, n-4] + 2
        a = secrets.randbelow(n - 4) + 2

        # Compute x = a^d mod n. We are calling r_0, ..., r_{j}, r_{j+1} as x.
        x = pow(a, c, n)

        # If x is congruent to 1 or n-1, continue to the next iteration
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)

             # If x is congruent to n-1, break the loop
            if x == n - 1:
                break
        else:
            return False

    # If n passes all iterations, it is probably prime
    return True

def find_next_prime(start):
    """
    Finds the probable next prime from `start` using Miller-Rabin Primality Test with 40 rounds each.
    It loops indefinitely until it finds and return a (probable) prime number.

    We are using 40 rounds as recommended here: https://stackoverflow.com/a/6330138
    """
    i = start
    while True:
        if miller_rabin(i):
            return i
        i += 1

def count_different_bits(seq1, seq2):
    # Ensure sequences have the same length
    max_len = max(len(seq1), len(seq2))
    seq1 = seq1.zfill(max_len)
    seq2 = seq2.zfill(max_len)
    
    count = 0
    for bit1, bit2 in zip(seq1, seq2):
        if bit1 != bit2:
            count += 1
    return count, max_len

class RSA_OAEP:
    def __init__(self, q, r, oaep_r):
        self.q = q
        self.r = r
        self.n = q * r
        self.phi = (q - 1) * (r - 1)
        self.public_key, self.private_key = self.generate_key_pair()
        self.oaep_r = oaep_r
        print('q: ', self.q)
        print('r: ', self.r)
        print('Public key: ', self.public_key)
        print('Private key: ', self.private_key)
        print('n: ', self.n)
        print('Φ(n): ', self.phi)
        print('OAEP R: ', self.oaep_r)
    
    def oaep_padding(self, nusp):
        """
        Performs Output Added Extension Protocol as defined in the exercise statement.

        It receives an integer 'nusp', that is the message to be padded. It will generate a
        NONCE 128-bit r and will format nusp into 32 bits, applying XORs and SHAs as given in
        the diagram.
        
        It is important to notice that, if nusp is greater than 32 bits, the program will probably
        fail silently, i.e., encryption will work without errors, but as the 32-bit message is
        complemented with zeros, decryption will only consider the message being the first 32, 
        leading to a different result than expected.
        """
        complemented_r = complement_to_n_bits(self.oaep_r, 256)

        message = "{:032b}".format(nusp)
        complemented_message = complement_to_n_bits(message, 128)

        gr = G(complemented_r)

        x = xor_128_bit_sequences(gr, complemented_message)
        complemented_x = complement_to_n_bits(x, 256)

        hx = G(complemented_x)
        y = xor_128_bit_sequences(hx, self.oaep_r)

        return x, y

    def oaep_unpadding(self, x, y):
        """
        Performs the OAEP unpadding as given in the exercise diagram.
        """
        complemented_x = complement_to_n_bits(x, 256)
        oaep_r = xor_128_bit_sequences(G(complemented_x), y)

        complemented_r = complement_to_n_bits(oaep_r, 256)
        complemented_message = xor_128_bit_sequences(x, G(complemented_r))
        message = complemented_message[:32]

        return message

    def generate_key_pair(self):
        """
        Generates a public-private key pair for RSA encryption.
        It selects a random integer 's' such that 's' and Euler's totient function of 'n' (phi(n))
        are coprime. It then computes the modular multiplicative inverse of 's' modulo 'phi(n)'
        to obtain the public key 'p'. The function returns the tuple (p, s).
        """
        # Find s such that s and phi(n) are coprime
        s = secrets.randbelow(self.phi)
        while gcd(s, self.phi) != 1:
            s = secrets.randbelow(self.phi)
        
        p = mod_inverse(s, self.phi)
        return p, s

    def encrypt(self, message):
        """
        Performs OAEP padding followed by RSA encryption. The function receives an integer
        and returns an encrypted integer.

        It raises ValueError if the OAEP-padded message is greater than the modulus 'n'.
        """
        print('Original message: ', message)
        x, y = self.oaep_padding(message)
        print('X||Y: ', x+y)

        padded_message = int(x + y, 2)
        if padded_message > self.n:
            raise ValueError('OAEP padded message cannot be greater than n. Choose greater primes for this message.')

        encrypted_message = pow(padded_message, self.public_key, self.n)
        encrypted_binary = "{:0256b}".format(encrypted_message)
        print('Integer encrypted message: ', encrypted_message)
        print('Binary encrypted message: ', encrypted_binary)
        return encrypted_message

    def decrypt(self, encrypted_message):
        """
        Performs RSA decryption followed by OAEP unpadding. The function receives the encrypted integer
        and returns the decrypted integer.
        """
        padded_message = pow(encrypted_message, self.private_key, self.n)
        padded_binary = "{:0256b}".format(padded_message)
        
        x = padded_binary[:128]
        y = padded_binary[128:] 
        decrypted_message = int(self.oaep_unpadding(x, y), 2)
        print('Integer decrypted message: ', decrypted_message)
        return decrypted_message


def main():
    # We are using NUSP concatenated 5 times because the OAEP padded message is usually
    # bigger than the version with 4 concatenations. The number below is 130 bits and n is 260 bits.
    big_nusp = 11796378_11796378_11796378_11796378_11796378
    q = find_next_prime(big_nusp) # 11796378_11796378_11796378_11796378_11796407
    r = find_next_prime(q+2) # 11796378_11796378_11796378_11796378_11796421
    oaep_r = generate_random_128_bit()
    rsaoaep = RSA_OAEP(q, r, oaep_r)

    # Below, we will execute the exercise 5) of this program-exercise, encrypting my NUSP
    # with and without the complemented bits and verify the Avalanche-Effect in the encrypted
    # binaries.
    print('\n\n########## No complemented bits ######')
    message = 11796378
    encrypted = rsaoaep.encrypt(message)
    original_binary = "{:0256b}".format(encrypted)
    if message != rsaoaep.decrypt(encrypted):
        raise SystemError('Failed to encrypt or decrypt.')

    print('\n\n########## Leftmost bit complemented ######')
    mask = 1 << 31
    message_with_one_complemented = message ^ mask # 2159280026
    encrypted_leftmost_complemented = rsaoaep.encrypt(message_with_one_complemented)
    leftmost_complemented_binary = "{:0256b}".format(encrypted_leftmost_complemented)
    if message_with_one_complemented != rsaoaep.decrypt(encrypted_leftmost_complemented):
        raise SystemError('Failed to encrypt or decrypt.')

    print('\n\n########## Two leftmost bits complemented ######')
    # 2 leftmost bits complemented
    mask = (1 << 31) | (1 << 30)
    message_with_two_complemented = message ^ mask # 3233021850
    encrypted_two_leftmost_complemented = rsaoaep.encrypt(message_with_two_complemented) 
    two_leftmost_complemented_binary = "{:0256b}".format(encrypted_two_leftmost_complemented)
    if message_with_two_complemented != rsaoaep.decrypt(encrypted_two_leftmost_complemented):
        raise SystemError('Failed to encrypt or decrypt.')

    diff, maxlen = count_different_bits(original_binary, leftmost_complemented_binary)
    print("Original and 1-complemented differ in {} bits out of {}".format(diff, maxlen))

    diff, maxlen = count_different_bits(original_binary, two_leftmost_complemented_binary)
    print("Original and 2-complemented differ in {} bits out of {}".format(diff, maxlen))
          
    diff, maxlen = count_different_bits(leftmost_complemented_binary, two_leftmost_complemented_binary)
    print("1-complemented and 2-complemented differ in {} bits out of {}".format(diff, maxlen))

main()

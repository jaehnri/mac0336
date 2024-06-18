import secrets
import random

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

def prime_factors(n):
    """
    Returns a list of all prime factors of the given number n.
    """
    factors = []
    
    # Handle the number of 2s that divide n
    while n % 2 == 0:
        factors.append(2)
        n //= 2
    
    # n must be odd at this point, thus a skip of 2 (i.e., i = i + 2) can be used
    for i in range(3, int(n**0.5) + 1, 2):
        # While i divides n, add i and divide n
        while n % i == 0:
            factors.append(i)
            n //= i
    
    # This condition is to check if n is a prime number greater than 2
    if n > 2:
        factors.append(n)
    
    return factors

def find_v(b, s, p):
    b_inv = mod_inverse(b, p)
    v = pow(b_inv, s, p)
    return v

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

class Authority:
    def __init__(self, nusp):
        self.q = self.find_next_prime(self.nusp_until_n_bits(nusp, 80))
        print("O valor de q de {} bits é {} ...".format(len(bin(self.q)[2:]), self.q))
        self.k = self.find_k()
        self.p = self.q * self.k + 1
        print("O valor de p de {} bits é {} ... .".format(len(bin(self.p)[2:]), self.p))
        self.g = self.find_generator()
        print("O valor de g de {} bits é {} ...".format(len(bin(self.g)[2:]), self.g))
        self.b = self.find_b()
        print("O valor de b de {} bits é {} ...".format(len(bin(self.b)[2:]), self.b))

    def nusp_until_n_bits(self, nusp, n):
        # [2:] removes the '0b' prefix
        binary_nusp = bin(nusp)[2:]
        
        # We concatenate the binary form until n bits rather than the actual number.
        # Then, we use the remainder as the most significant bits to complete.
        reps = n // len(binary_nusp)
        remainder = n % len(binary_nusp)
        concatenated_bits = binary_nusp[:remainder] + binary_nusp * reps
        
        return int(concatenated_bits, 2)
    
    def find_next_prime(self, start):
        """
        Find the probable next prime from `start` using Miller-Rabin Primality Test with 40 rounds each.
        It loops indefinitely until it finds and return a (probable) prime number.

        We are using 40 rounds as recommended here: https://stackoverflow.com/a/6330138
        """
        i = start
        while True:
            if miller_rabin(i):
                return i
            i += 1

    def find_k(self):
        """
        Find a k such that:
        1. p = kq + 1. 
        2. p is prime.
        3. p is 512-bit.
        4. k is easily factorable.

        k is found through a left and right strategy, where left is a 
        small integer and right is a big power of 2.
        """
        bits_q = self.q.bit_length()
        left = 2
        while True:
            right = 2 ** (512 - bits_q - left.bit_length())
            k = left * right

            if miller_rabin(k * self.q + 1):
                return k
            left += 1

    def is_generator(self, g, phi_p, factors):
        for factor in factors:
            if pow(g, phi_p // factor, self.p) == 1:
                return False
        return True

    def find_generator(self):
        phi_p = self.p - 1
        factors = prime_factors(self.k)
        factors.append(self.q)

        g = 2
        while True:
            if self.is_generator(g, phi_p, factors):
                return g
            g += 1

    def find_b(self):
        """
        Compute b = g^((p-1)/q) mod p.
        """
        phi_p = self.p - 1
        exponent = phi_p // self.q
        return pow(self.g, exponent, self.p)

nusp = 11796378
authority = Authority(nusp)

s = random.randint(1, authority.q - 1)
print("O valor de s de {} bits é {} ...".format(len(bin(s)[2:]), s))

v = find_v(authority.b, s, authority.p)
print("O valor de v de {} bits é {} ...".format(len(bin(v)[2:]), v))

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


def nusp_until_n_bits(nusp, n):
    # [2:] removes the '0b' prefix
    binary_nusp = bin(nusp)[2:]
    
    # We concatenate the binary form until n bits rather than the actual number.
    # Then, we use the remainder as the most significant bits to complete.
    reps = n // len(binary_nusp)
    remainder = n % len(binary_nusp)
    concatenated_bits = binary_nusp[:remainder] + binary_nusp * reps
    
    return int(concatenated_bits, 2)

def first_512_bit_number():
    return 2 ** 511

def prime_factors(n):
    """Returns a list of all prime factors of the given number n."""
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

def find_k(q):
    """
    Find a k such that:
     1. p = kq + 1. 
     2. p is prime.
     3. p is 512-bit.
     4. k is easily factorable.

    k is found through a left and right strategy, where left is a 
    small integer and right is a big power of 2.
    """
    bits_q = q.bit_length()
    left = 2
    while True:
        right = 2 ** (512 - bits_q - left.bit_length())
        k = left * right

        if miller_rabin(k * q + 1):
            return k
        left += 1

def is_generator(g, phi_p, factors):
    for factor in factors:
        if pow(g, phi_p // factor, p) == 1:
            return False
    return True

def find_generator(p, q, k):
    phi_p = p - 1
    factors = prime_factors(k)
    factors.append(q)

    g = 2
    while True:
        if is_generator(g, phi_p, factors):
            return g
        g += 1

def list_b(p, g, q):
    """Compute b = g^((p-1)/q) mod p."""
    phi_p = p - 1
    exponent = phi_p // q
    return pow(g, exponent, p)

nusp = 11796378
concatenated_nusp = nusp_until_n_bits(nusp, 80)

q = find_next_prime(concatenated_nusp)
print("O valor de q de {} bits é {} ...".format(len(bin(q)[2:]), q))

k = find_k(q)
p = q * k + 1
print("O valor de p de {} bits é {} ... .".format(len(bin(p)[2:]), p))

g = find_generator(p, q, k)
print("O valor de g de {} bits é {} ... .".format(len(bin(g)[2:]), g))

b = list_b(p, g, q)
print("O valor de b de {} bits é {} ... .".format(len(bin(b)[2:]), b))

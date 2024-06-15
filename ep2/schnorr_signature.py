import secrets

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

nusp = 11796378
concatenated_nusp = nusp_until_n_bits(nusp, 80)

q = find_next_prime(concatenated_nusp)
print("O valor de q de {} bits é {} ...".format(len(bin(q)[2:]), q))

# We start k as the first 512 bit number divided by p. This way,
# the loop below will only yield primes with at least 512 bits.
k = first_512_bit_number() // q
p = 0

while not miller_rabin(p):
    p = k * q + 1
    k += 1
print("O valor de p de {} bits é {} ... .".format(len(bin(p)[2:]), p))

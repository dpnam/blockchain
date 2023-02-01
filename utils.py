# Refs: https://github.com/NikolaiT/Large-Primes-for-RSA/blob/master/generate_primes.py
import re
import random
import math

def fermat_primality_test(p, s=5):
    """
    a^(p-1) ≡ 1 mod p
    Input: prime candidate p and security paramter s
    Output: either p is a composite (always trues), or
            p is a prime (with probability)
    """
    if p == 2:
        return True
    if not p & 1: # if p is even, number cant be a prime
        return False

    for i in range(s):
        a = random.randrange(2, p-2)
        x = pow(a, p-1, p) # a**(p-1) % p
        if x != 1:
            return False
    return True

def square_and_multiply(x, k, p=None):
    """
    Square and Multiply Algorithm
    Parameters: positive integer x and integer exponent k,
                optional modulus p
    Returns: x**k or x**k mod p when p is given
    """
    b = bin(k).lstrip('0b')
    r = 1
    for i in b:
        r = r**2
        if i == '1':
            r = r * x
        if p:
            r %= p
    return r

def miller_rabin_primality_test(p, s=5):
    if p == 2: # 2 is the only prime that is even
        return True
    if not (p & 1): # n is a even number and can't be prime
        return False

    p1 = p - 1
    u = 0
    r = p1  # p-1 = 2**u * r

    while r % 2 == 0:
        r >>= 1
        u += 1

    # at this stage p-1 = 2**u * r  holds
    assert p-1 == 2**u * r

    def witness(a):
        """
        Returns: True, if there is a witness that p is not prime.
                False, when p might be prime
        """
        z = square_and_multiply(a, r, p)
        if z == 1:
            return False

        for i in range(u):
            z = square_and_multiply(a, 2**i * r, p)
            if z == p1:
                return False
        return True

    for j in range(s):
        a = random.randrange(2, p-2)
        if witness(a):
            return False

    return True

def generate_primes(n=512, k=1):
    """
    Generates prime numbers with bitlength n.
    Stops after the generation of k prime numbers.
    Caution: The numbers tested for primality start at
    a random place, but the tests are drawn with the integers
    following from the random start.
    """
    assert k > 0
    assert n > 0 and n < 4096

    # follows from the prime number theorem
    necessary_steps = math.floor( math.log(2**n) / 2 )
    # get n random bits as our first number to test for primality
    x = random.getrandbits(n)

    primes = []

    while k>0:
        if miller_rabin_primality_test(x, s=7):
            primes.append(x)
            k = k-1
        x = x+1

    return primes

def generate_prime(n=512):
    return generate_primes(n, k=1)[0]

# Refs: https://gist.github.com/nakov/60d62bdf4067ea72b7832ce9f71ae079
def modular_sqrt(a, p):

    def legendre_symbol(a, p):
        """ Compute the Legendre symbol a|p using
            Euler's criterion. p is a prime, a is
            relatively prime to p (if p divides
            a, then a|p = 0)
            Returns 1 if a has a square root modulo
            p, -1 otherwise.
        """
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls

    """ Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.
        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.
        0 is returned is no square root exists for
        these a and p.
        The Tonelli-Shanks algorithm is used (except
        for some simple cases in which the solution
        is known from an identity). This algorithm
        runs in polynomial time (unless the
        generalized Riemann hypothesis is false).
    """
    # Simple cases
    if legendre_symbol(a, p) != 1:
        return -1
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    #
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information
    #

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    #
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

# Ref: https://gist.github.com/bellbind/1414867/03b4b2dd79b41e65e51716076e5e2b0171628a10
import collections
Coord = collections.namedtuple("Coord", ["x", "y"])

def inv(n, p):
    """div on PN modulo a/b mod p as a * inv(b, p) mod p
    >>> assert n * inv(n, p) % p == 1
    """
    return pow(n, -1, p)

def sqrt(n, p):
    """sqrt on PN modulo: it may not exist
    >>> assert (sqrt(n, p) ** 2) % p == n
    """
    
    assert n < p
    
    x = modular_sqrt(n, p)
    if x == -1:
        raise Exception("not found")
        
    return (x, p - x)

class EC(object):
    # init Elliptic Curve in Field (finite)
    def __init__(self, a, b, p):
        """elliptic curve (E) as: (y**2 = x**3 + a * x + b) mod p
        - a, b: params of curve formula
        - p: (large) prime number
        """
        
        # check conditions
        assert 0 < a and a < p and 0 < b and b < p and p > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % p != 0
        
        # assign params
        self.a = a
        self.b = b
        self.p = p
        
        # extra point O "at infinity"
        self.O = Coord(0, 0)
        
        pass
        
    # check pint 
    def is_valid(self, P):
        if P == self.O: return True
        
        left = (P.y ** 2) % self.p
        right = ((P.x ** 3) + self.a * P.x + self.b) % self.p
        
        return left == right
    
    # caculate y from x
    def at(self, x):
        """find points on curve at x
        - x: int < p
        - returns: ((x, y), (x,-y)) or not found exception
        >>> P, mP = ec.at(x)
        >>> assert P.x == mP.x and P.x == x
        >>> assert P.x == mP.x and P.x == x
        >>> assert ec.neg(P) == mP
        >>> assert ec.is_valid(P) and ec.is_valid(mP)
        """
        assert x < self.p
        
        ysq = (x ** 3 + self.a * x + self.b) % self.p
        y, my = sqrt(ysq, self.p)
        return Coord(x, y), Coord(x, my)
    
    # get negative of P
    def neg(self, P):
        """negate P
        >>> assert ec.is_valid(ec.neg(P))
        """
        return Coord(P.x, -P.y % self.p)
    
    # add 2 point
    def add(self, P1, P2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1, p2) line
        >>>  R = ec.add(P1, P2)
        >>> assert ec.is_valid(P1)
        >>> assert ec.add(R, ec.neg(P2)) == P1
        """
        if P1 == self.O: return P2
        
        if P2 == self.O: return P1
        
        if P1.x == P2.x and P1.y != P2.y:
            # p1 + -p1 == 0
            return self.O
        
        if P1 != P2:
            l = (P2.y - P1.y) * inv(P2.x - P1.x, self.p) % self.p
            pass
        else:
            # P1 + P1: use tangent line of p1 as (P1, P1) line
            l = (3 * P1.x * P1.x + self.a) * inv(2 * P1.y, self.p) % self.p
            pass
        
        x = (l * l - P1.x - P2.x) % self.p
        y = (l * (P1.x - x) - P1.y) % self.p
        
        return Coord(x, y)
    
    # mul point
    def mul(self, P, n):
        """n times <mul> of elliptic curve
        >>> R = ec.mul(P, n)
        >>> assert ec.is_valid(R)
        """
        Q = P
        R = self.O
        while n  > 0:
            if n%2 == 1: R = self.add(R, Q)
            Q = self.add(Q, Q)
            n = int(n/2)
            
        return R
    pass

# func: convert decimal to hexadecimal with buff_size of hexadecimal
def dec_to_hex(dec_number, buff_size):
    dec_str = hex(dec_number)[2:]
    for i in range(buff_size - len(dec_str)):
        dec_str = '0' + dec_str
    dec_str = '0x' + dec_str
    
    return dec_str

# func: encrypt_ecc_unit
def encrypt_ecc_unit(hex_str):
    # convert hex to dec
    x = int('0x' + hex_str, 0)
    
    # convert x in (x', y') in Elliptic
    i = 0
    while (i <= 10000):
        fake_x = x*l + i
        try: 
            M, mM = curr_ec.at(fake_x)

            condition_1 = (M.x == mM.x) and (M.x == fake_x)
            condition_2 = (curr_ec.neg(M) == mM)
            condition_3 = curr_ec.is_valid(M) and curr_ec.is_valid(mM)

            if condition_1 and condition_2 and condition_3:
                break
        except:
            pass

        i += 1
            
    # encrypt
    Q_a = curr_ec.mul(P, n_a)
    k = 11

    # C_1 = k*P 
    C_1 = curr_ec.mul(P, k)

    # C_2 = M + k*Q_a
    C_2 = curr_ec.add(M, curr_ec.mul(Q_a, k))
    
    # sent encrypt
    _C_1 = dec_to_hex(C_1.x, buff_size_output)[2:] + dec_to_hex(C_1.y, buff_size_output)[2:]
    _C_2 = dec_to_hex(C_2.x, buff_size_output)[2:] + dec_to_hex(C_2.y, buff_size_output)[2:]
    
    # return
    return _C_1, _C_2

# func: decrypt_ecc_unit
def decrypt_ecc_unit(_C_1, _C_2):
    # get C_1, C_2
    C_1_x = int('0x' + _C_1[:buff_size_output], 0)
    C_1_y = int('0x' + _C_1[buff_size_output:], 0)
    C_1 = Coord(x=C_1_x, y=C_1_y)
    
    C_2_x = int('0x' + _C_2[:buff_size_output], 0)
    C_2_y = int('0x' + _C_2[buff_size_output:], 0)
    C_2 = Coord(x=C_2_x, y=C_2_y)
    
    # C_2 – n_a*C_1
    decrypt_point = curr_ec.add(C_2, curr_ec.neg(curr_ec.mul(C_1, n_a)))
    decrypt_x = int(decrypt_point.x//l)
    
    # return
    return hex(decrypt_x)[2:]

# func: encrypt_ecc_msg
def encrypt_ecc_msg(msg):
    # convert to hex_msg
    hex_msg = msg.encode('utf-8').hex()
    
    # params
    _C_1_s = ''
    _C_2_s = ''

    # loop encrypt with buff_size_input
    curr = 0
    while curr < len(hex_msg):
        sub_hex_msg = hex_msg[curr:curr+buff_size_input]

        _C_1, _C_2 = encrypt_ecc_unit(sub_hex_msg)

        _C_1_s += _C_1
        _C_2_s += _C_2

        curr += buff_size_input

    # return 
    return _C_1_s, _C_2_s

# func: decrypt_ecc_msg
def decrypt_ecc_msg(_C_1_s, _C_2_s):
    # params
    dec_decrypt_s = ''
    len_encrypt = len(_C_1_s) # or len(_C_2_s)

    # loop decrypt with buff_size_output
    curr = 0
    while curr < len_encrypt:
        _C_1 = _C_1_s[curr:curr+buff_size_output*2]
        _C_2 = _C_2_s[curr:curr+buff_size_output*2]

        dec_decrypt = str(decrypt_ecc_unit(_C_1, _C_2))
        dec_decrypt_s += dec_decrypt

        curr += buff_size_output*2

    # convert string to hex
    decrypt_msg = bytes.fromhex(hex(int('0x'+ dec_decrypt_s, 0))[2:]).decode('utf-8')
    
    # return
    return decrypt_msg

########################### SAMPLE ###########################
# Key Exchange
## init elliptic curve
p = generate_prime(n=160)
a = random.getrandbits(128) % p
b = random.getrandbits(128) % p
curr_ec = EC(a, b, p)
buff_size_output = len((hex((1 << p.bit_length()) - 1))[2:])

## random point P
while True:
    try:
        x = random.getrandbits(128) % p
        P = Coord(x=x, y=curr_ec.at(x)[0].y)
        break
        
    except:
        pass
    
## create Q_a and Q_b
n_a = 123456789
Q_a = curr_ec.mul(P, n_a)

n_b = 987654321
Q_b = curr_ec.mul(P, n_b)

## share secret point
assert curr_ec.mul(Q_a, n_b) == curr_ec.mul(Q_b, n_a)
K = curr_ec.mul(Q_a, n_b)
share_secret_key = '0x' + dec_to_hex(K.x, buff_size_output)[2:] + dec_to_hex(K.y, buff_size_output)[2:]

print(K)
print('Share Secret Key: ' + share_secret_key)

# Encrypt/Decrypt
## https://crypto.stackexchange.com/questions/76340/how-to-create-an-ec-point-from-a-plaintext-message-for-encryption
p = generate_prime(n=160)
a = random.getrandbits(128) % p
b = random.getrandbits(128) % p

curr_ec = EC(a, b, p)

## params
l = 41
fake_p = p // l

buff_size_input = len((hex((1 << fake_p.bit_length()) - 1))[2:]) - 1
buff_size_output = len((hex((1 << p.bit_length()) - 1))[2:])

## public key
while True:
    try:
        x = random.getrandbits(128) % p
        P = Coord(x=x, y=curr_ec.at(x)[0].y)
        break
    except:
        pass

## private key
n_a = 124124

## meassge
msg = ''' 
- Đặng Phương Nam 3131 trường đại học khoa học tự nhiên thành phố hồ chí minh 
- abc adadwadawd
'''

## encrypt
_C_1_s, _C_2_s = encrypt_ecc_msg(msg)
decrypt_msg = decrypt_ecc_msg(_C_1_s, _C_2_s)

print(_C_1_s)
print(_C_2_s)
print(decrypt_msg)